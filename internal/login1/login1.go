// Package login1 serves org.freedesktop.login1 on the system bus: power
// actions, sessions and the seat, including the device brokering libseat's
// logind backend relies on.
package login1

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-logind/internal/seat"
)

const (
	busName      = "org.freedesktop.login1"
	managerPath  = dbus.ObjectPath("/org/freedesktop/login1")
	managerIface = "org.freedesktop.login1.Manager"
	seatPath     = dbus.ObjectPath("/org/freedesktop/login1/seat/seat0")
	seatIface    = "org.freedesktop.login1.Seat"
	sessionIface = "org.freedesktop.login1.Session"
	uidMin       = 1000
)

// Session is one login or greeter session.
type Session struct {
	ID         string
	UID        uint32
	Name       string
	Leader     int
	Class      string
	Type       string
	VT         int
	Started    time.Time
	controller string
	devices    map[[2]uint32]*seat.Device
	props      *prop.Properties
	idle       bool
	locked     bool
}

func (s *Session) path() dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/login1/session/_3" + escape(s.ID))
}

func escape(id string) string {
	var b strings.Builder
	for _, r := range id {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "_%02x", r)
		}
	}
	return b.String()
}

// Service is the login1 implementation.
type Service struct {
	conn        *dbus.Conn
	mu          sync.Mutex
	sessions    map[string]*Session
	active      string
	displayUser string
	displayVT   int
	terminal    seat.Terminal
	greeterUID  uint32
	inhibitors  []inhibitor
	seatProps   *prop.Properties
}

type inhibitor struct {
	what, who, why, mode string
	uid                  uint32
	pid                  uint32
	fd                   *os.File
}

// New connects to the system bus and exports the manager and the seat.
// displayUser owns the persistent compositor, which runs as a service rather
// than a child of sinty-logind; its processes get a display session on vt.
func New(displayUser string, vt int) (*Service, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	s := &Service{conn: conn, sessions: map[string]*Session{}, displayUser: displayUser, displayVT: vt}
	if u, err := user.Lookup(displayUser); err == nil {
		if n, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			s.greeterUID = uint32(n)
		}
	}
	if err := s.export(); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := conn.RequestName(busName, dbus.NameFlagReplaceExisting|dbus.NameFlagDoNotQueue)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		conn.Close()
		return nil, fmt.Errorf("%s is owned by another process", busName)
	}
	seat.WatchVT(s.vtChanged)
	go s.watchControllers()
	return s, nil
}

type manager struct{ s *Service }
type seatObject struct{ s *Service }
type sessionObject struct {
	s  *Service
	id string
}

func (s *Service) export() error {
	m := &manager{s}
	if err := s.conn.Export(m, managerPath, managerIface); err != nil {
		return err
	}
	if _, err := prop.Export(s.conn, managerPath, prop.Map{managerIface: {
		"IdleHint":             {Value: false, Emit: prop.EmitFalse},
		"PreparingForSleep":    {Value: false, Emit: prop.EmitTrue},
		"PreparingForShutdown": {Value: false, Emit: prop.EmitTrue},
		"Docked":               {Value: false, Emit: prop.EmitFalse},
		"HandlePowerKey":       {Value: "poweroff", Emit: prop.EmitFalse},
		"NAutoVTs":             {Value: uint32(0), Emit: prop.EmitFalse},
	}}); err != nil {
		return err
	}
	if err := s.conn.Export(&seatObject{s}, seatPath, seatIface); err != nil {
		return err
	}
	seatProps, err := prop.Export(s.conn, seatPath, prop.Map{seatIface: {
		"Id":            {Value: "seat0", Emit: prop.EmitFalse},
		"CanGraphical":  {Value: true, Emit: prop.EmitFalse},
		"CanTTY":        {Value: true, Emit: prop.EmitFalse},
		"ActiveSession": {Value: activeRef{"", "/"}, Emit: prop.EmitTrue, Callback: nil},
		"Sessions":      {Value: []activeRef{}, Emit: prop.EmitTrue},
	}})
	if err != nil {
		return err
	}
	s.seatProps = seatProps
	for _, alias := range []dbus.ObjectPath{"/org/freedesktop/login1/session/self", "/org/freedesktop/login1/session/auto"} {
		if err := s.conn.Export(&sessionObject{s: s, id: ""}, alias, sessionIface); err != nil {
			return err
		}
	}
	node := &introspect.Node{
		Name: string(managerPath),
		Interfaces: []introspect.Interface{introspect.IntrospectData, prop.IntrospectData,
			{Name: managerIface, Methods: introspect.Methods(m)}},
	}
	return s.conn.Export(introspect.NewIntrospectable(node), managerPath, "org.freedesktop.DBus.Introspectable")
}

type activeRef struct {
	ID   string
	Path dbus.ObjectPath
}

func (s *Service) callerPID(sender dbus.Sender) (uint32, error) {
	var pid uint32
	err := s.conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, string(sender)).Store(&pid)
	return pid, err
}

func (s *Service) callerUID(sender dbus.Sender) (uint32, error) {
	var uid uint32
	err := s.conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid)
	return uid, err
}

func denied(action string, uid uint32) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []interface{}{fmt.Sprintf("not authorized to %s (caller uid %d)", action, uid)})
}

func failed(err error) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{err.Error()})
}

func (s *Service) mayPower(sender dbus.Sender) (uint32, bool) {
	uid, err := s.callerUID(sender)
	if err != nil {
		return 0, false
	}
	return uid, uid == 0 || uid >= uidMin || uid == s.greeterUID
}

// SessionStarted records a session the greeter manager started.
func (s *Service) SessionStarted(id string, uid uint32, name string, leader int, class string, vt int) {
	s.mu.Lock()
	sess := &Session{ID: id, UID: uid, Name: name, Leader: leader, Class: class, Type: "wayland", VT: vt, Started: time.Now(), devices: map[[2]uint32]*seat.Device{}}
	s.sessions[id] = sess
	s.mu.Unlock()
	s.exportSession(sess)
	if class == "user" {
		s.setActive(id)
	}
	s.conn.Emit(managerPath, managerIface+".SessionNew", id, sess.path())
}

// SessionEnded forgets a session and closes its devices.
func (s *Service) SessionEnded(id string) {
	s.mu.Lock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	if sess != nil {
		for _, d := range sess.devices {
			d.Close()
		}
	}
	wasActive := s.active == id
	if wasActive {
		s.active = ""
	}
	s.mu.Unlock()
	if sess == nil {
		return
	}
	s.conn.Export(nil, sess.path(), sessionIface)
	s.conn.Emit(managerPath, managerIface+".SessionRemoved", id, sess.path())
	if wasActive {
		s.activateDisplay()
	}
	s.refreshSeat()
}

func (s *Service) exportSession(sess *Session) {
	obj := &sessionObject{s: s, id: sess.ID}
	s.conn.Export(obj, sess.path(), sessionIface)
	uidPath := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/login1/user/_%d", sess.UID))
	props, err := prop.Export(s.conn, sess.path(), prop.Map{sessionIface: {
		"Id":         {Value: sess.ID, Emit: prop.EmitFalse},
		"User":       {Value: userRef{sess.UID, uidPath}, Emit: prop.EmitFalse},
		"Name":       {Value: sess.Name, Emit: prop.EmitFalse},
		"Seat":       {Value: activeRef{"seat0", seatPath}, Emit: prop.EmitFalse},
		"VTNr":       {Value: uint32(sess.VT), Emit: prop.EmitFalse},
		"TTY":        {Value: fmt.Sprintf("tty%d", sess.VT), Emit: prop.EmitFalse},
		"Display":    {Value: "", Emit: prop.EmitFalse},
		"Remote":     {Value: false, Emit: prop.EmitFalse},
		"Service":    {Value: "sinty-logind", Emit: prop.EmitFalse},
		"Type":       {Value: sess.Type, Emit: prop.EmitTrue},
		"Class":      {Value: sess.Class, Emit: prop.EmitFalse},
		"Leader":     {Value: uint32(sess.Leader), Emit: prop.EmitFalse},
		"Active":     {Value: false, Emit: prop.EmitTrue},
		"State":      {Value: "online", Emit: prop.EmitTrue},
		"IdleHint":   {Value: false, Emit: prop.EmitTrue},
		"LockedHint": {Value: false, Emit: prop.EmitTrue},
		"Timestamp":  {Value: uint64(sess.Started.UnixMicro()), Emit: prop.EmitFalse},
	}})
	if err == nil {
		s.mu.Lock()
		sess.props = props
		s.mu.Unlock()
	}
	s.refreshSeat()
}

type userRef struct {
	UID  uint32
	Path dbus.ObjectPath
}

func (s *Service) refreshSeat() {
	s.mu.Lock()
	var list []activeRef
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		list = append(list, activeRef{id, s.sessions[id].path()})
	}
	active := activeRef{"", "/"}
	if sess, ok := s.sessions[s.active]; ok {
		active = activeRef{sess.ID, sess.path()}
	}
	s.mu.Unlock()
	if list == nil {
		list = []activeRef{}
	}
	if s.seatProps != nil {
		s.seatProps.SetMust(seatIface, "ActiveSession", active)
		s.seatProps.SetMust(seatIface, "Sessions", list)
	}
}

// displaySession returns, creating it if needed, the session of the
// persistent compositor for a process of the display user.
func (s *Service) displaySession(pid uint32) *Session {
	s.mu.Lock()
	for _, sess := range s.sessions {
		if sess.Class == "greeter" && sess.ID == "c0" {
			s.mu.Unlock()
			return sess
		}
	}
	s.mu.Unlock()
	u, err := user.Lookup(s.displayUser)
	if err != nil {
		return nil
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	sess := &Session{ID: "c0", UID: uint32(uid), Name: u.Username, Leader: int(pid), Class: "greeter", Type: "wayland", VT: s.displayVT, Started: time.Now(), devices: map[[2]uint32]*seat.Device{}}
	s.mu.Lock()
	s.sessions["c0"] = sess
	s.mu.Unlock()
	s.exportSession(sess)
	if s.active == "" {
		s.setActive("c0")
	}
	return sess
}

func (s *Service) activateDisplay() {
	s.mu.Lock()
	_, ok := s.sessions["c0"]
	s.mu.Unlock()
	if ok {
		s.setActive("c0")
	}
}

func (s *Service) setActive(id string) {
	s.mu.Lock()
	if s.active == id {
		s.mu.Unlock()
		return
	}
	previous := s.sessions[s.active]
	next := s.sessions[id]
	s.active = id
	s.mu.Unlock()
	if previous != nil && previous != next && previous.ID != "c0" {
		s.setProp(previous, "Active", false)
	}
	if next != nil {
		s.setProp(next, "Active", true)
	}
	s.refreshSeat()
}

func (s *Service) setProp(sess *Session, name string, value interface{}) {
	if sess.props != nil {
		sess.props.SetMust(sessionIface, name, value)
	}
}

func (s *Service) sessionForPID(pid uint32) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := int(pid); p > 1; p = parentPID(p) {
		for _, sess := range s.sessions {
			if sess.Leader == p {
				return sess
			}
		}
	}
	return nil
}

func parentPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	text := string(data)
	end := strings.LastIndexByte(text, ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fields[1])
	return n
}

func uidOf(pid uint32) (uint32, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				n, err := strconv.ParseUint(fields[0], 10, 32)
				return uint32(n), err == nil
			}
		}
	}
	return 0, false
}

func (s *Service) resolve(pid uint32) *Session {
	if sess := s.sessionForPID(pid); sess != nil {
		return sess
	}
	if uid, ok := uidOf(pid); ok && uid == s.greeterUID && s.greeterUID != 0 {
		return s.displaySession(pid)
	}
	return nil
}

func noSession(what string) *dbus.Error {
	return dbus.NewError("org.freedesktop.login1.NoSessionForPID", []interface{}{what})
}

// GetSession returns the object path of a session.
func (m *manager) GetSession(sender dbus.Sender, id string) (dbus.ObjectPath, *dbus.Error) {
	if id == "" || id == "self" || id == "auto" {
		pid, err := m.s.callerPID(sender)
		if err != nil {
			return "", failed(err)
		}
		if sess := m.s.resolve(pid); sess != nil {
			return sess.path(), nil
		}
		return "", noSession("caller does not belong to a session")
	}
	m.s.mu.Lock()
	sess, ok := m.s.sessions[id]
	m.s.mu.Unlock()
	if !ok {
		return "", dbus.NewError("org.freedesktop.login1.NoSuchSession", []interface{}{"no session " + id})
	}
	return sess.path(), nil
}

// GetSessionByPID returns the session a process belongs to.
func (m *manager) GetSessionByPID(sender dbus.Sender, pid uint32) (dbus.ObjectPath, *dbus.Error) {
	if pid == 0 {
		var err error
		if pid, err = m.s.callerPID(sender); err != nil {
			return "", failed(err)
		}
	}
	if sess := m.s.resolve(pid); sess != nil {
		return sess.path(), nil
	}
	return "", noSession(fmt.Sprintf("PID %d does not belong to any known session", pid))
}

// GetSeat returns the seat object.
func (m *manager) GetSeat(id string) (dbus.ObjectPath, *dbus.Error) {
	if id == "seat0" || id == "" || id == "self" || id == "auto" {
		return seatPath, nil
	}
	return "", dbus.NewError("org.freedesktop.login1.NoSuchSeat", []interface{}{"no seat " + id})
}

type sessionEntry struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

// ListSessions lists every session.
func (m *manager) ListSessions() ([]sessionEntry, *dbus.Error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	var out []sessionEntry
	for _, sess := range m.s.sessions {
		out = append(out, sessionEntry{sess.ID, sess.UID, sess.Name, "seat0", sess.path()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type seatEntry struct {
	ID   string
	Path dbus.ObjectPath
}

// ListSeats lists the single seat.
func (m *manager) ListSeats() ([]seatEntry, *dbus.Error) {
	return []seatEntry{{"seat0", seatPath}}, nil
}

func (m *manager) power(sender dbus.Sender, action string, run func()) *dbus.Error {
	uid, ok := m.s.mayPower(sender)
	if !ok {
		return denied(action, uid)
	}
	go func() {
		m.s.conn.Emit(managerPath, managerIface+".PrepareForShutdown", true)
		time.Sleep(200 * time.Millisecond)
		run()
	}()
	return nil
}

func runFirst(commands ...string) {
	for _, c := range commands {
		if err := exec.Command(c).Run(); err == nil {
			return
		}
	}
}

// Reboot restarts the machine.
func (m *manager) Reboot(sender dbus.Sender, interactive bool) *dbus.Error {
	return m.power(sender, "Reboot", func() { runFirst("/bin/reboot", "/sbin/reboot") })
}

// PowerOff turns the machine off.
func (m *manager) PowerOff(sender dbus.Sender, interactive bool) *dbus.Error {
	return m.power(sender, "PowerOff", func() { runFirst("/bin/poweroff", "/sbin/poweroff") })
}

// Halt turns the machine off.
func (m *manager) Halt(sender dbus.Sender, interactive bool) *dbus.Error {
	return m.PowerOff(sender, interactive)
}

// Suspend sleeps to memory.
func (m *manager) Suspend(sender dbus.Sender, interactive bool) *dbus.Error {
	uid, ok := m.s.mayPower(sender)
	if !ok {
		return denied("Suspend", uid)
	}
	go m.s.sleep("mem")
	return nil
}

// Hibernate is not offered: the root filesystem is read-only and swap is
// compressed memory, so there is nowhere to write the image.
func (m *manager) Hibernate(sender dbus.Sender, interactive bool) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.NotSupported", []interface{}{"hibernation is not available"})
}

func (s *Service) sleep(state string) {
	s.conn.Emit(managerPath, managerIface+".PrepareForSleep", true)
	s.waitInhibitors("sleep", 5*time.Second)
	if err := os.WriteFile("/sys/power/state", []byte(state), 0); err != nil {
		log.Printf("suspend: %v", err)
	}
	s.conn.Emit(managerPath, managerIface+".PrepareForSleep", false)
}

// CanReboot reports whether Reboot is allowed.
func (m *manager) CanReboot() (string, *dbus.Error) { return "yes", nil }

// CanPowerOff reports whether PowerOff is allowed.
func (m *manager) CanPowerOff() (string, *dbus.Error) { return "yes", nil }

// CanHalt reports whether Halt is allowed.
func (m *manager) CanHalt() (string, *dbus.Error) { return "yes", nil }

// CanSuspend reports whether Suspend is possible.
func (m *manager) CanSuspend() (string, *dbus.Error) {
	data, err := os.ReadFile("/sys/power/state")
	if err == nil && strings.Contains(string(data), "mem") {
		return "yes", nil
	}
	return "na", nil
}

// CanHibernate reports that hibernation is not available.
func (m *manager) CanHibernate() (string, *dbus.Error) { return "na", nil }

// CanHybridSleep reports that hybrid sleep is not available.
func (m *manager) CanHybridSleep() (string, *dbus.Error) { return "na", nil }

// CanSuspendThenHibernate reports that it is not available.
func (m *manager) CanSuspendThenHibernate() (string, *dbus.Error) { return "na", nil }

// Inhibit returns a descriptor that holds back sleep or shutdown until it
// is closed, so applications can save state first.
func (m *manager) Inhibit(sender dbus.Sender, what, who, why, mode string) (dbus.UnixFD, *dbus.Error) {
	uid, _ := m.s.callerUID(sender)
	pid, _ := m.s.callerPID(sender)
	r, w, err := os.Pipe()
	if err != nil {
		return -1, failed(err)
	}
	m.s.mu.Lock()
	m.s.inhibitors = append(m.s.inhibitors, inhibitor{what: what, who: who, why: why, mode: mode, uid: uid, pid: pid, fd: r})
	m.s.mu.Unlock()
	go func() {
		buf := make([]byte, 1)
		r.Read(buf)
		m.s.mu.Lock()
		for i, in := range m.s.inhibitors {
			if in.fd == r {
				m.s.inhibitors = append(m.s.inhibitors[:i], m.s.inhibitors[i+1:]...)
				break
			}
		}
		m.s.mu.Unlock()
		r.Close()
	}()
	return dbus.UnixFD(w.Fd()), nil
}

type inhibitorEntry struct {
	What, Who, Why, Mode string
	UID, PID             uint32
}

// ListInhibitors lists the active inhibitors.
func (m *manager) ListInhibitors() ([]inhibitorEntry, *dbus.Error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	var out []inhibitorEntry
	for _, in := range m.s.inhibitors {
		out = append(out, inhibitorEntry{in.what, in.who, in.why, in.mode, in.uid, in.pid})
	}
	return out, nil
}

func (s *Service) waitInhibitors(what string, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		busy := false
		s.mu.Lock()
		for _, in := range s.inhibitors {
			if in.mode == "delay" && strings.Contains(in.what, what) {
				busy = true
			}
		}
		s.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (o *sessionObject) session(sender dbus.Sender) (*Session, *dbus.Error) {
	if o.id != "" {
		o.s.mu.Lock()
		sess, ok := o.s.sessions[o.id]
		o.s.mu.Unlock()
		if !ok {
			return nil, dbus.NewError("org.freedesktop.login1.NoSuchSession", []interface{}{"the session is gone"})
		}
		return sess, nil
	}
	pid, err := o.s.callerPID(sender)
	if err != nil {
		return nil, failed(err)
	}
	if sess := o.s.resolve(pid); sess != nil {
		return sess, nil
	}
	return nil, noSession("caller does not belong to a session")
}

func (o *sessionObject) owner(sender dbus.Sender, sess *Session, action string) *dbus.Error {
	uid, err := o.s.callerUID(sender)
	if err != nil {
		return failed(err)
	}
	if uid != 0 && uid != sess.UID {
		return denied(action, uid)
	}
	return nil
}

// TakeControl makes the caller the session controller, the only process
// allowed to take devices.
func (o *sessionObject) TakeControl(sender dbus.Sender, force bool) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	if derr := o.owner(sender, sess, "TakeControl"); derr != nil {
		return derr
	}
	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if sess.controller != "" && sess.controller != string(sender) && !force {
		return dbus.NewError("org.freedesktop.login1.DeviceIsTaken", []interface{}{"the session already has a controller"})
	}
	sess.controller = string(sender)
	go o.s.terminal.Graphics(sess.VT)
	return nil
}

func (s *Service) watchControllers() {
	if err := s.conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged")); err != nil {
		log.Printf("watching bus names: %v", err)
		return
	}
	signals := make(chan *dbus.Signal, 64)
	s.conn.Signal(signals)
	for sig := range signals {
		if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
			continue
		}
		name, _ := sig.Body[0].(string)
		owner, _ := sig.Body[2].(string)
		if owner != "" {
			continue
		}
		s.mu.Lock()
		for _, sess := range s.sessions {
			if sess.controller == name {
				for key, d := range sess.devices {
					d.Close()
					delete(sess.devices, key)
				}
				sess.controller = ""
			}
		}
		s.mu.Unlock()
	}
}

// ReleaseControl gives up control and every device.
func (o *sessionObject) ReleaseControl(sender dbus.Sender) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if sess.controller != string(sender) {
		return dbus.NewError("org.freedesktop.login1.NotInControl", []interface{}{"not the session controller"})
	}
	for k, d := range sess.devices {
		d.Close()
		delete(sess.devices, k)
	}
	sess.controller = ""
	return nil
}

// TakeDevice opens a device node for the session controller.
func (o *sessionObject) TakeDevice(sender dbus.Sender, major, minor uint32) (dbus.UnixFD, bool, *dbus.Error) {
	sess, derr := o.session(sender)
	if derr != nil {
		return -1, false, derr
	}
	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if sess.controller != string(sender) {
		return -1, false, dbus.NewError("org.freedesktop.login1.NotInControl", []interface{}{"not the session controller"})
	}
	key := [2]uint32{major, minor}
	if _, taken := sess.devices[key]; taken {
		return -1, false, dbus.NewError("org.freedesktop.login1.DeviceIsTaken", []interface{}{"device already taken"})
	}
	vt := seat.ActiveVT()
	active := vt == 0 || sess.VT == 0 || vt == sess.VT
	dev, err := seat.Open(major, minor, active)
	if err != nil {
		return -1, false, failed(err)
	}
	sess.devices[key] = dev
	return dbus.UnixFD(dev.Fd()), dev.Paused, nil
}

// ReleaseDevice closes a device.
func (o *sessionObject) ReleaseDevice(sender dbus.Sender, major, minor uint32) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if sess.controller != string(sender) {
		return dbus.NewError("org.freedesktop.login1.NotInControl", []interface{}{"not the session controller"})
	}
	key := [2]uint32{major, minor}
	if dev, ok := sess.devices[key]; ok {
		dev.Close()
		delete(sess.devices, key)
	}
	return nil
}

// PauseDeviceComplete acknowledges a pause.
func (o *sessionObject) PauseDeviceComplete(sender dbus.Sender, major, minor uint32) *dbus.Error {
	return nil
}

// Activate brings the session to the foreground.
func (o *sessionObject) Activate(sender dbus.Sender) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	if sess.VT > 0 && seat.ActiveVT() != sess.VT {
		if err := seat.Activate(sess.VT); err != nil {
			return failed(err)
		}
	}
	o.s.setActive(sess.ID)
	return nil
}

// SetType records the session type a compositor reports.
func (o *sessionObject) SetType(sender dbus.Sender, kind string) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.mu.Lock()
	sess.Type = kind
	o.s.mu.Unlock()
	o.s.setProp(sess, "Type", kind)
	return nil
}

// SetIdleHint records whether the session is idle.
func (o *sessionObject) SetIdleHint(sender dbus.Sender, idle bool) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.setProp(sess, "IdleHint", idle)
	return nil
}

// SetLockedHint records whether the session is locked.
func (o *sessionObject) SetLockedHint(sender dbus.Sender, locked bool) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.setProp(sess, "LockedHint", locked)
	return nil
}

// Lock asks the session to lock its screen.
func (o *sessionObject) Lock(sender dbus.Sender) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.conn.Emit(sess.path(), sessionIface+".Lock")
	return nil
}

// Unlock asks the session to unlock its screen.
func (o *sessionObject) Unlock(sender dbus.Sender) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	o.s.conn.Emit(sess.path(), sessionIface+".Unlock")
	return nil
}

// Terminate ends the session by stopping its leader process group, which
// sends the user back to the greeter.
func (o *sessionObject) Terminate(sender dbus.Sender) *dbus.Error {
	sess, derr := o.session(sender)
	if derr != nil {
		return derr
	}
	uid, err := o.s.callerUID(sender)
	if err != nil {
		return failed(err)
	}
	if uid != 0 && (uid < uidMin || uid != sess.UID) {
		return denied("Terminate", uid)
	}
	if sess.ID == "c0" {
		return dbus.NewError("org.freedesktop.DBus.Error.NotSupported", []interface{}{"the display session cannot be terminated"})
	}
	go func() {
		killGroup(sess.Leader, syscall.SIGTERM)
		time.Sleep(5 * time.Second)
		killGroup(sess.Leader, syscall.SIGKILL)
	}()
	return nil
}

// SetBrightness writes a backlight or LED brightness for the session user.
func (o *sessionObject) SetBrightness(sender dbus.Sender, subsystem, name string, brightness uint32) *dbus.Error {
	uid, err := o.s.callerUID(sender)
	if err != nil {
		return failed(err)
	}
	if uid != 0 && uid < uidMin {
		return denied("SetBrightness", uid)
	}
	if (subsystem != "backlight" && subsystem != "leds") || name == "" || strings.ContainsAny(name, "/") || strings.Contains(name, "..") {
		return dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{fmt.Sprintf("invalid brightness target %s/%s", subsystem, name)})
	}
	base := fmt.Sprintf("/sys/class/%s/%s", subsystem, name)
	if data, err := os.ReadFile(base + "/max_brightness"); err == nil {
		if max, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); err == nil && uint64(brightness) > max {
			brightness = uint32(max)
		}
	}
	if err := os.WriteFile(base+"/brightness", []byte(strconv.FormatUint(uint64(brightness), 10)), 0); err != nil {
		return failed(err)
	}
	return nil
}

// SwitchTo switches the foreground terminal.
func (o *seatObject) SwitchTo(sender dbus.Sender, vt uint32) *dbus.Error {
	uid, err := o.s.callerUID(sender)
	if err != nil {
		return failed(err)
	}
	if uid != 0 && uid < uidMin && uid != o.s.greeterUID {
		return denied("SwitchTo", uid)
	}
	if vt == 0 || vt > 63 {
		return dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"invalid terminal"})
	}
	if err := seat.Activate(int(vt)); err != nil {
		return failed(err)
	}
	return nil
}

// ActivateSession brings a session to the foreground.
func (o *seatObject) ActivateSession(sender dbus.Sender, id string) *dbus.Error {
	o.s.mu.Lock()
	sess, ok := o.s.sessions[id]
	o.s.mu.Unlock()
	if !ok {
		return dbus.NewError("org.freedesktop.login1.NoSuchSession", []interface{}{"no session " + id})
	}
	return (&sessionObject{s: o.s, id: sess.ID}).Activate(sender)
}

func (s *Service) vtChanged(vt int) {
	s.mu.Lock()
	var display *Session
	for _, sess := range s.sessions {
		if sess.ID == "c0" {
			display = sess
		}
	}
	s.mu.Unlock()
	if display == nil {
		return
	}
	if vt == display.VT {
		s.resume(display)
	} else {
		s.pause(display)
	}
}

func (s *Service) pause(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, d := range sess.devices {
		if d.Paused {
			continue
		}
		d.Pause()
		kind := "force"
		if d.IsDRM() {
			kind = "pause"
		}
		s.conn.Emit(sess.path(), sessionIface+".PauseDevice", key[0], key[1], kind)
	}
	if sess.props != nil {
		sess.props.SetMust(sessionIface, "Active", false)
	}
}

func (s *Service) resume(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, d := range sess.devices {
		if !d.Paused {
			continue
		}
		if err := d.Resume(); err != nil {
			log.Printf("resuming %d:%d: %v", key[0], key[1], err)
			continue
		}
		s.conn.Emit(sess.path(), sessionIface+".ResumeDevice", key[0], key[1], dbus.UnixFD(d.Fd()))
	}
	if sess.props != nil {
		sess.props.SetMust(sessionIface, "Active", true)
	}
}

func killGroup(pid int, sig syscall.Signal) {
	if pid > 1 {
		syscall.Kill(-pid, sig)
	}
}
