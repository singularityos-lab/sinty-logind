// Package greet runs the greeter and starts user sessions. It speaks the
// greetd IPC protocol, so greeters written for greetd work unchanged.
package greet

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/singularityos-lab/sinty-logind/internal/config"
	"github.com/singularityos-lab/sinty-logind/internal/pam"
)

// Service is the PAM service used to authenticate and open sessions.
const Service = "greetd"

// Tracker is told about sessions as they start and end.
type Tracker interface {
	SessionStarted(id string, uid uint32, name string, leader int, class string, vt int)
	SessionEnded(id string)
}

// Manager runs the greeter, authenticates and starts sessions.
type Manager struct {
	cfg     *config.Config
	socket  string
	tracker Tracker

	mu      sync.Mutex
	pending *pendingSession
	nextID  int
}

// Transaction is the part of a PAM transaction the manager uses.
type Transaction interface {
	Authenticate() error
	AcctMgmt() error
	EstablishCredentials() error
	DeleteCredentials() error
	OpenSession() error
	CloseSession() error
	PutEnv(name, value string) error
	Env() []string
	End()
}

// StartPAM begins a PAM transaction; tests replace it.
var StartPAM = func(service, user string, conv pam.Conversation) (Transaction, error) {
	return pam.Start(service, user, conv)
}

type pendingSession struct {
	tx   Transaction
	user string
	cmd  []string
	env  []string
}

// New returns a manager for the configuration.
func New(cfg *config.Config, socket string, tracker Tracker) *Manager {
	return &Manager{cfg: cfg, socket: socket, tracker: tracker, nextID: 1}
}

// Run serves greeters forever: the initial session first, then the greeter,
// each user session it starts, and the greeter again.
func (m *Manager) Run() error {
	listener, err := m.listen()
	if err != nil {
		return err
	}
	go m.accept(listener)
	if m.cfg.Initial != nil && m.cfg.Initial.Command != "" {
		if err := m.runUnauthenticated(*m.cfg.Initial); err != nil {
			log.Printf("initial session: %v", err)
		}
	}
	backoff := time.Second
	for {
		started := time.Now()
		if err := m.runGreeter(); err != nil {
			log.Printf("greeter: %v", err)
		}
		m.mu.Lock()
		next := m.pending
		m.pending = nil
		m.mu.Unlock()
		if next != nil {
			if err := m.runSession(next); err != nil {
				log.Printf("session for %s: %v", next.user, err)
			}
			backoff = time.Second
			continue
		}
		if time.Since(started) < 5*time.Second {
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

func (m *Manager) listen() (net.Listener, error) {
	os.Remove(m.socket)
	l, err := net.Listen("unix", m.socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(m.socket, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (m *Manager) accept(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("ipc: %v", err)
			return
		}
		go m.serve(conn.(*net.UnixConn))
	}
}

func lookup(name string) (*user.User, uint32, uint32, []uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	var groups []uint32
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	return u, uint32(uid), uint32(gid), groups, nil
}

func baseEnv(u *user.User, shell string) []string {
	if shell == "" {
		shell = "/bin/sh"
	}
	return []string{
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"SHELL=" + shell,
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
}

func merge(base []string, more ...[]string) []string {
	index := map[string]int{}
	var out []string
	add := func(entry string) {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			return
		}
		if i, seen := index[name]; seen {
			out[i] = entry
			return
		}
		index[name] = len(out)
		out = append(out, entry)
	}
	for _, e := range base {
		add(e)
	}
	for _, list := range more {
		for _, e := range list {
			add(e)
		}
	}
	return out
}

func userShell(name string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == name {
			return fields[6]
		}
	}
	return ""
}

func (m *Manager) runGreeter() error {
	u, uid, gid, groups, err := lookup(m.cfg.Default.User)
	if err != nil {
		return err
	}
	env := merge(baseEnv(u, userShell(u.Username)), []string{
		"GREETD_SOCK=" + m.socket,
		"XDG_SESSION_CLASS=greeter",
		"XDG_SESSION_TYPE=wayland",
		"XDG_SEAT=seat0",
		"XDG_VTNR=" + strconv.Itoa(m.cfg.VT),
	})
	if err := os.Chown(m.socket, int(uid), int(gid)); err != nil {
		return err
	}
	cmd := exec.Command("/bin/sh", "-c", m.cfg.Default.Command)
	cmd.Env = env
	cmd.Dir = u.HomeDir
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	if _, err := os.Stat(u.HomeDir); err != nil {
		cmd.Dir = "/"
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	id := m.newID()
	m.tracker.SessionStarted(id, uid, u.Username, cmd.Process.Pid, "greeter", m.cfg.VT)
	err = cmd.Wait()
	m.tracker.SessionEnded(id)
	return err
}

func (m *Manager) newID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := strconv.Itoa(m.nextID)
	m.nextID++
	return id
}

func (m *Manager) runUnauthenticated(s config.Session) error {
	tx, err := StartPAM(Service, s.User, func(pam.Style, string) (string, error) {
		return "", errors.New("no interactive conversation for this session")
	})
	if err != nil {
		return err
	}
	return m.runSession(&pendingSession{tx: tx, user: s.User, cmd: []string{"/bin/sh", "-c", s.Command}})
}

func (m *Manager) runSession(p *pendingSession) error {
	defer p.tx.End()
	u, uid, gid, groups, err := lookup(p.user)
	if err != nil {
		return err
	}
	id := m.newID()
	for k, v := range map[string]string{
		"XDG_SESSION_TYPE":  "wayland",
		"XDG_SESSION_CLASS": "user",
		"XDG_SEAT":          "seat0",
		"XDG_VTNR":          strconv.Itoa(m.cfg.VT),
		"XDG_SESSION_ID":    id,
	} {
		p.tx.PutEnv(k, v)
	}
	if err := p.tx.EstablishCredentials(); err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	if err := p.tx.OpenSession(); err != nil {
		p.tx.DeleteCredentials()
		return fmt.Errorf("open session: %w", err)
	}
	defer func() {
		p.tx.CloseSession()
		p.tx.DeleteCredentials()
	}()
	if len(p.cmd) == 0 {
		return errors.New("empty session command")
	}
	env := merge(baseEnv(u, userShell(u.Username)), p.tx.Env(), p.env)
	cmd := exec.Command(p.cmd[0], p.cmd[1:]...)
	if !strings.HasPrefix(p.cmd[0], "/") {
		if path, err := exec.LookPath(p.cmd[0]); err == nil {
			cmd.Path = path
		}
	}
	cmd.Env = env
	cmd.Dir = u.HomeDir
	if _, err := os.Stat(u.HomeDir); err != nil {
		cmd.Dir = "/"
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	if err := cmd.Start(); err != nil {
		return err
	}
	m.tracker.SessionStarted(id, uid, u.Username, cmd.Process.Pid, "user", m.cfg.VT)
	err = cmd.Wait()
	m.tracker.SessionEnded(id)
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	return err
}

type request struct {
	Type     string   `json:"type"`
	Username string   `json:"username"`
	Response *string  `json:"response"`
	Cmd      []string `json:"cmd"`
	Env      []string `json:"env"`
}

type response struct {
	Type            string `json:"type"`
	ErrorType       string `json:"error_type,omitempty"`
	Description     string `json:"description,omitempty"`
	AuthMessageType string `json:"auth_message_type,omitempty"`
	AuthMessage     string `json:"auth_message,omitempty"`
}

func read(r io.Reader) (*request, error) {
	var size uint32
	if err := binary.Read(r, binary.NativeEndian, &size); err != nil {
		return nil, err
	}
	if size == 0 || size > 1<<16 {
		return nil, errors.New("invalid message size")
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var req request
	if err := json.Unmarshal(buf, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func write(w io.Writer, resp response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.NativeEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type prompt struct {
	style   pam.Style
	message string
}

type auth struct {
	user     string
	prompts  chan prompt
	answers  chan *string
	done     chan error
	tx       Transaction
	finished bool
}

func startAuth(username string) *auth {
	a := &auth{user: username, prompts: make(chan prompt), answers: make(chan *string), done: make(chan error, 1)}
	go func() {
		runtime.LockOSThread()
		tx, err := StartPAM(Service, username, func(style pam.Style, message string) (string, error) {
			a.prompts <- prompt{style, message}
			answer := <-a.answers
			if answer == nil {
				if style == pam.PromptEchoOff || style == pam.PromptEchoOn {
					return "", errors.New("cancelled")
				}
				return "", nil
			}
			return *answer, nil
		})
		if err != nil {
			a.done <- err
			return
		}
		if err := tx.Authenticate(); err != nil {
			tx.End()
			a.done <- err
			return
		}
		if err := tx.AcctMgmt(); err != nil {
			tx.End()
			a.done <- err
			return
		}
		a.tx = tx
		a.done <- nil
	}()
	return a
}

func (a *auth) next() response {
	select {
	case p := <-a.prompts:
		kind := "secret"
		switch p.style {
		case pam.PromptEchoOn:
			kind = "visible"
		case pam.TextInfo:
			kind = "info"
		case pam.ErrorMsg:
			kind = "error"
		}
		return response{Type: "auth_message", AuthMessageType: kind, AuthMessage: p.message}
	case err := <-a.done:
		a.finished = true
		if err != nil {
			return response{Type: "error", ErrorType: "auth_error", Description: describe(err)}
		}
		return response{Type: "success"}
	}
}

func (a *auth) cancel() {
	if a.finished {
		if a.tx != nil {
			a.tx.End()
			a.tx = nil
		}
		return
	}
	for {
		select {
		case a.answers <- nil:
		case <-a.prompts:
		case <-a.done:
			a.finished = true
			if a.tx != nil {
				a.tx.End()
				a.tx = nil
			}
			return
		}
	}
}

func describe(err error) string {
	var perr *pam.Error
	if errors.As(err, &perr) {
		switch perr.Code {
		case 7, 9, 10:
			return "Authentication failed"
		}
		return perr.Message
	}
	return err.Error()
}

func (m *Manager) serve(conn *net.UnixConn) {
	defer conn.Close()
	var current *auth
	defer func() {
		if current != nil {
			current.cancel()
		}
	}()
	for {
		req, err := read(conn)
		if err != nil {
			return
		}
		var resp response
		switch req.Type {
		case "create_session":
			if current != nil {
				resp = response{Type: "error", ErrorType: "error", Description: "a session is already being configured"}
				break
			}
			if req.Username == "" {
				resp = response{Type: "error", ErrorType: "error", Description: "no user name"}
				break
			}
			current = startAuth(req.Username)
			resp = current.next()
			if resp.Type == "error" {
				current = nil
			}
		case "post_auth_message_response":
			if current == nil || current.finished {
				resp = response{Type: "error", ErrorType: "error", Description: "no authentication in progress"}
				break
			}
			current.answers <- req.Response
			resp = current.next()
			if resp.Type == "error" {
				current = nil
			}
		case "start_session":
			if current == nil || !current.finished || current.tx == nil {
				resp = response{Type: "error", ErrorType: "error", Description: "the session is not authenticated"}
				break
			}
			if len(req.Cmd) == 0 {
				resp = response{Type: "error", ErrorType: "error", Description: "no command"}
				break
			}
			m.mu.Lock()
			if m.pending != nil {
				m.pending.tx.End()
			}
			m.pending = &pendingSession{tx: current.tx, user: current.user, cmd: req.Cmd, env: req.Env}
			m.mu.Unlock()
			current.tx = nil
			current = nil
			resp = response{Type: "success"}
		case "cancel_session":
			if current != nil {
				current.cancel()
				current = nil
			}
			resp = response{Type: "success"}
		default:
			resp = response{Type: "error", ErrorType: "error", Description: "unknown request"}
		}
		if err := write(conn, resp); err != nil {
			return
		}
	}
}

func writeRequest(w io.Writer, req map[string]interface{}) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.NativeEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readResponse(r io.Reader) (response, error) {
	var size uint32
	var resp response
	if err := binary.Read(r, binary.NativeEndian, &size); err != nil {
		return resp, err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return resp, err
	}
	err := json.Unmarshal(buf, &resp)
	return resp, err
}
