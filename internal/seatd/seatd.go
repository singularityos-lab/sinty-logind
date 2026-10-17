// Package seatd serves the seatd protocol, so compositors using libseat get
// their DRM and input devices from sinty-logind without a separate seatd.
// The behaviour follows seatd's VT-bound seat: one active client per VT,
// devices revoked when the VT is released and given back when it returns.
package seatd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	clientOpenSeat      = 1
	clientCloseSeat     = 2
	clientOpenDevice    = 3
	clientCloseDevice   = 4
	clientDisableSeat   = 5
	clientSwitchSession = 6
	clientPing          = 7

	serverSeatOpened      = 1<<15 + 1
	serverSeatClosed      = 1<<15 + 2
	serverDeviceOpened    = 1<<15 + 3
	serverDeviceClosed    = 1<<15 + 4
	serverDisableSeat     = 1<<15 + 5
	serverEnableSeat      = 1<<15 + 6
	serverPong            = 1<<15 + 7
	serverSessionSwitched = 1<<15 + 8
	serverSeatDisabled    = 1<<15 + 9
	serverError           = 1<<15 + 0x7fff

	maxPathLen = 256
	maxDevices = 128

	vtSetMode     = 0x5602
	vtGetState    = 0x5603
	vtActivate    = 0x5606
	vtRelDisp     = 0x5605
	vtAckAcq      = 0x02
	vtAuto        = 0x00
	vtProcess     = 0x01
	kdSkbMode     = 0x4b45
	kdSetMode     = 0x4b3a
	kOff          = 0x04
	kUnicode      = 0x03
	kdText        = 0x00
	kdGraphics    = 0x01
	drmSetMaster  = 0x641e
	drmDropMaster = 0x641f
	eviocRevoke   = 0x40044591
	hidiocRevoke  = 0x4004480d
)

type deviceType int

const (
	typeDRM deviceType = iota
	typeEvdev
	typeHidraw
)

type device struct {
	id     int32
	path   string
	kind   deviceType
	file   *os.File
	refs   int
	active bool
}

type clientState int

const (
	stateNew clientState = iota
	stateActive
	statePendingDisable
	stateDisabled
	stateClosed
)

type client struct {
	conn    *net.UnixConn
	writeMu sync.Mutex
	session int
	state   clientState
	inSeat  bool
	devices []*device
}

// Server is the seat and its clients.
type Server struct {
	mu      sync.Mutex
	clients []*client
	active  *client
	next    *client
	curVT   int
}

// Listen serves the protocol on path, owned by group with mode 0770.
func Listen(path string, gid int) (*Server, error) {
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o770); err != nil {
		l.Close()
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			l.Close()
			return nil, err
		}
	}
	s := &Server{curVT: -1}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range signals {
			if sig == syscall.SIGUSR1 {
				s.vtRelease()
			} else {
				s.vtActivate()
			}
		}
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Printf("seat: %v", err)
				return
			}
			c := &client{conn: conn.(*net.UnixConn), session: -1}
			go s.serve(c)
		}
	}()
	return s, nil
}

func ioctl(fd uintptr, req, arg uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}

func openTTY(vt int) (*os.File, error) {
	return os.OpenFile(fmt.Sprintf("/dev/tty%d", vt), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
}

func currentVT() int {
	f, err := openTTY(0)
	if err != nil {
		return -1
	}
	defer f.Close()
	var st struct{ active, signal, state uint16 }
	if err := ioctl(f.Fd(), vtGetState, uintptr(unsafe.Pointer(&st))); err != nil {
		return -1
	}
	return int(st.active)
}

type vtMode struct {
	mode   int8
	waitv  int8
	relsig int16
	acqsig int16
	frsig  int16
}

func setProcessSwitching(f *os.File, enable bool) error {
	m := vtMode{mode: vtAuto}
	if enable {
		m = vtMode{mode: vtProcess, relsig: int16(syscall.SIGUSR1), acqsig: int16(syscall.SIGUSR2)}
	}
	return ioctl(f.Fd(), vtSetMode, uintptr(unsafe.Pointer(&m)))
}

func vtOpen(vt int) error {
	f, err := openTTY(vt)
	if err != nil {
		return err
	}
	defer f.Close()
	setProcessSwitching(f, true)
	ioctl(f.Fd(), kdSkbMode, kOff)
	ioctl(f.Fd(), kdSetMode, kdGraphics)
	return nil
}

func vtClose(vt int) {
	f, err := openTTY(vt)
	if err != nil {
		return
	}
	defer f.Close()
	setProcessSwitching(f, true)
	ioctl(f.Fd(), kdSkbMode, kUnicode)
	ioctl(f.Fd(), kdSetMode, kdText)
}

func (s *Server) vtSwitch(vt int) error {
	f, err := openTTY(s.curVT)
	if err != nil {
		return err
	}
	defer f.Close()
	setProcessSwitching(f, true)
	return ioctl(f.Fd(), vtActivate, uintptr(vt))
}

func (s *Server) vtAck(release bool) {
	f, err := openTTY(s.curVT)
	if err != nil {
		return
	}
	defer f.Close()
	if release {
		ioctl(f.Fd(), vtRelDisp, 1)
	} else {
		ioctl(f.Fd(), vtRelDisp, vtAckAcq)
	}
}

func (c *client) send(opcode uint16, body []byte, fd int) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	msg := make([]byte, 4+len(body))
	binary.NativeEndian.PutUint16(msg[0:], opcode)
	binary.NativeEndian.PutUint16(msg[2:], uint16(len(body)))
	copy(msg[4:], body)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	_, _, err := c.conn.WriteMsgUnix(msg, oob, nil)
	return err
}

func (c *client) sendError(err error) error {
	code := int32(unix.EIO)
	var errno syscall.Errno
	if errors.As(err, &errno) {
		code = int32(errno)
	}
	body := make([]byte, 4)
	binary.NativeEndian.PutUint32(body, uint32(code))
	return c.send(serverError, body, -1)
}

func (s *Server) serve(c *client) {
	defer func() {
		s.mu.Lock()
		if c.inSeat {
			s.removeClient(c)
		}
		s.mu.Unlock()
		c.conn.Close()
	}()
	header := make([]byte, 4)
	for {
		if _, err := io.ReadFull(c.conn, header); err != nil {
			return
		}
		opcode := binary.NativeEndian.Uint16(header[0:])
		size := int(binary.NativeEndian.Uint16(header[2:]))
		body := make([]byte, size)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return
		}
		if err := s.handle(c, opcode, body); err != nil {
			log.Printf("seat client %d: %v", c.session, err)
			return
		}
	}
}

func (s *Server) handle(c *client, opcode uint16, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch opcode {
	case clientOpenSeat:
		if len(body) != 0 {
			return errors.New("invalid open_seat message")
		}
		if err := s.addClient(c); err != nil {
			return err
		}
		name := "seat0\x00"
		reply := make([]byte, 2+len(name))
		binary.NativeEndian.PutUint16(reply, uint16(len(name)))
		copy(reply[2:], name)
		if err := c.send(serverSeatOpened, reply, -1); err != nil {
			return err
		}
		s.openClient(c)
		return nil
	case clientCloseSeat:
		if len(body) != 0 || !c.inSeat {
			return errors.New("invalid close_seat message")
		}
		s.removeClient(c)
		return c.send(serverSeatClosed, nil, -1)
	case clientOpenDevice:
		if !c.inSeat || len(body) < 2 {
			return errors.New("invalid open_device message")
		}
		n := int(binary.NativeEndian.Uint16(body))
		if n != len(body)-2 || n == 0 || n > maxPathLen || body[len(body)-1] != 0 || strings.IndexByte(string(body[2:len(body)-1]), 0) >= 0 {
			return errors.New("invalid device path")
		}
		dev, err := s.openDevice(c, string(body[2:len(body)-1]))
		if err != nil {
			return c.sendError(err)
		}
		dup, err := unix.FcntlInt(dev.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			s.closeDevice(c, dev)
			return c.sendError(err)
		}
		defer unix.Close(dup)
		reply := make([]byte, 4)
		binary.NativeEndian.PutUint32(reply, uint32(dev.id))
		return c.send(serverDeviceOpened, reply, dup)
	case clientCloseDevice:
		if !c.inSeat || len(body) != 4 {
			return errors.New("invalid close_device message")
		}
		id := int32(binary.NativeEndian.Uint32(body))
		for _, d := range c.devices {
			if d.id == id && id != 0 {
				s.closeDevice(c, d)
				return c.send(serverDeviceClosed, nil, -1)
			}
		}
		return c.sendError(unix.EBADF)
	case clientSwitchSession:
		if !c.inSeat || len(body) != 4 {
			return errors.New("invalid switch_session message")
		}
		if err := s.setNextSession(c, int(int32(binary.NativeEndian.Uint32(body)))); err != nil {
			return c.sendError(err)
		}
		return c.send(serverSessionSwitched, nil, -1)
	case clientDisableSeat:
		if !c.inSeat || len(body) != 0 {
			return errors.New("invalid disable_seat message")
		}
		if c.state != statePendingDisable {
			return c.sendError(unix.EBUSY)
		}
		c.state = stateDisabled
		if s.active == c {
			s.active = nil
			s.activate()
		}
		return c.send(serverSeatDisabled, nil, -1)
	case clientPing:
		return c.send(serverPong, nil, -1)
	}
	return fmt.Errorf("unknown opcode %d", opcode)
}

func (s *Server) addClient(c *client) error {
	if c.inSeat {
		return unix.EBUSY
	}
	if s.active != nil && s.active.state != statePendingDisable {
		return unix.EBUSY
	}
	if c.session != -1 {
		return unix.EINVAL
	}
	s.curVT = currentVT()
	if s.curVT == -1 {
		return unix.EINVAL
	}
	if s.active != nil {
		for _, other := range s.clients {
			if other.session == s.curVT {
				return unix.EBUSY
			}
		}
	}
	c.session = s.curVT
	c.inSeat = true
	s.clients = append(s.clients, c)
	log.Printf("seat client added on VT %d", c.session)
	return nil
}

func (s *Server) openClient(c *client) error {
	if c.state != stateNew && c.state != stateDisabled {
		return unix.EALREADY
	}
	if s.active != nil {
		return unix.EBUSY
	}
	if err := vtOpen(c.session); err != nil {
		return err
	}
	for _, d := range c.devices {
		activateDevice(d)
	}
	c.state = stateActive
	s.active = c
	return c.send(serverEnableSeat, nil, -1)
}

func (s *Server) activate() {
	if s.active != nil {
		return
	}
	var next *client
	switch {
	case s.next != nil:
		next, s.next = s.next, nil
	case len(s.clients) == 0 || s.curVT == -1:
		return
	default:
		for _, c := range s.clients {
			if c.session == s.curVT {
				next = c
				break
			}
		}
	}
	if next != nil {
		s.openClient(next)
	}
}

func (s *Server) removeClient(c *client) {
	if s.next == c {
		s.next = nil
	}
	for i, other := range s.clients {
		if other == c {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			break
		}
	}
	for len(c.devices) > 0 {
		d := c.devices[0]
		d.refs = 1
		s.closeDevice(c, d)
	}
	wasCurrent := s.active == c
	if wasCurrent {
		s.active = nil
		s.activate()
	}
	if wasCurrent && s.active == nil {
		vtClose(s.curVT)
	} else if !wasCurrent && c.state != stateClosed {
		vtClose(c.session)
	}
	c.state = stateClosed
	c.inSeat = false
	log.Printf("seat client on VT %d removed", c.session)
}

func classify(path string) (deviceType, bool) {
	switch {
	case strings.HasPrefix(path, "/dev/input/event"):
		return typeEvdev, true
	case strings.HasPrefix(path, "/dev/dri/"):
		return typeDRM, true
	case strings.HasPrefix(path, "/dev/hidraw"):
		return typeHidraw, true
	}
	return 0, false
}

func (s *Server) openDevice(c *client, path string) (*device, error) {
	if c.state != stateActive {
		return nil, unix.EPERM
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return nil, err
	}
	kind, ok := classify(real)
	if !ok {
		return nil, unix.ENOENT
	}
	id := int32(1)
	for _, d := range c.devices {
		if d.path == real {
			d.refs++
			return d, nil
		}
		if d.id >= id {
			id = d.id + 1
		}
	}
	if len(c.devices) >= maxDevices {
		return nil, unix.EMFILE
	}
	fd, err := unix.Open(real, unix.O_RDWR|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), real)
	if kind == typeDRM {
		if err := ioctl(f.Fd(), drmSetMaster, 0); err != nil {
			log.Printf("%s: could not become DRM master: %v", real, err)
		}
	}
	d := &device{id: id, path: real, kind: kind, file: f, refs: 1, active: true}
	c.devices = append(c.devices, d)
	return d, nil
}

func deactivateDevice(d *device) {
	if !d.active {
		return
	}
	switch d.kind {
	case typeDRM:
		ioctl(d.file.Fd(), drmDropMaster, 0)
	case typeEvdev:
		ioctl(d.file.Fd(), eviocRevoke, 0)
	case typeHidraw:
		ioctl(d.file.Fd(), hidiocRevoke, 0)
	}
	d.active = false
}

func activateDevice(d *device) {
	if d.active || d.kind != typeDRM {
		return
	}
	if err := ioctl(d.file.Fd(), drmSetMaster, 0); err != nil {
		log.Printf("%s: could not become DRM master: %v", d.path, err)
	}
	d.active = true
}

func (s *Server) closeDevice(c *client, d *device) {
	d.refs--
	if d.refs > 0 {
		return
	}
	for i, other := range c.devices {
		if other == d {
			c.devices = append(c.devices[:i], c.devices[i+1:]...)
			break
		}
	}
	deactivateDevice(d)
	d.file.Close()
}

func (s *Server) disableClient(c *client) {
	if c.state != stateActive {
		return
	}
	for _, d := range c.devices {
		deactivateDevice(d)
	}
	c.state = statePendingDisable
	c.send(serverDisableSeat, nil, -1)
}

func (s *Server) setNextSession(c *client, session int) error {
	if c.state != stateActive {
		return unix.EPERM
	}
	if session <= 0 {
		return unix.EINVAL
	}
	if session == c.session || s.next != nil {
		return nil
	}
	return s.vtSwitch(session)
}

func (s *Server) vtRelease() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.curVT = currentVT()
	if s.active != nil {
		s.disableClient(s.active)
	}
	s.vtAck(true)
	s.curVT = -1
}

func (s *Server) vtActivate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.curVT = currentVT()
	s.vtAck(false)
	if s.active == nil {
		s.activate()
	}
}
