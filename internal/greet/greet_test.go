package greet

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/sinty-logind/internal/config"
	"github.com/singularityos-lab/sinty-logind/internal/pam"
)

type fakeTx struct {
	conv  pam.Conversation
	ended bool
}

func (t *fakeTx) Authenticate() error {
	answer, err := t.conv(pam.PromptEchoOff, "PIN:")
	if err != nil {
		return err
	}
	if answer != "246810" {
		return &pam.Error{Code: 7, Message: "Authentication failure"}
	}
	return nil
}
func (t *fakeTx) AcctMgmt() error                 { return nil }
func (t *fakeTx) EstablishCredentials() error     { return nil }
func (t *fakeTx) DeleteCredentials() error        { return nil }
func (t *fakeTx) OpenSession() error              { return nil }
func (t *fakeTx) CloseSession() error             { return nil }
func (t *fakeTx) PutEnv(name, value string) error { return nil }
func (t *fakeTx) Env() []string                   { return nil }
func (t *fakeTx) End()                            { t.ended = true }

func dial(t *testing.T) (*Manager, net.Conn) {
	t.Helper()
	StartPAM = func(service, user string, conv pam.Conversation) (Transaction, error) {
		if user == "nobody-here" {
			return nil, errors.New("unknown user")
		}
		return &fakeTx{conv: conv}, nil
	}
	dir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := New(&config.Config{VT: 1}, filepath.Join(dir, "g.sock"), nil)
	l, err := m.listen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go m.accept(l)
	conn, err := net.Dial("unix", m.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return m, conn
}

func call(t *testing.T, conn net.Conn, req map[string]interface{}) response {
	t.Helper()
	if err := writeRequest(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLoginFlow(t *testing.T) {
	m, conn := dial(t)
	r := call(t, conn, map[string]interface{}{"type": "create_session", "username": "prova"})
	if r.Type != "auth_message" || r.AuthMessageType != "secret" || r.AuthMessage != "PIN:" {
		t.Fatalf("first reply %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "post_auth_message_response", "response": "000000"})
	if r.Type != "error" || r.ErrorType != "auth_error" || r.Description != "Authentication failed" {
		t.Fatalf("wrong PIN reply %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "create_session", "username": "prova"})
	if r.Type != "auth_message" {
		t.Fatalf("retry reply %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "post_auth_message_response", "response": "246810"})
	if r.Type != "success" {
		t.Fatalf("right PIN reply %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "start_session", "cmd": []string{"/usr/bin/singularity-desktop-session"}})
	if r.Type != "success" {
		t.Fatalf("start reply %+v", r)
	}
	m.mu.Lock()
	pending := m.pending
	m.mu.Unlock()
	if pending == nil || pending.user != "prova" || pending.cmd[0] != "/usr/bin/singularity-desktop-session" {
		t.Fatalf("pending session %+v", pending)
	}
}

func TestStartBeforeAuthIsRefused(t *testing.T) {
	_, conn := dial(t)
	r := call(t, conn, map[string]interface{}{"type": "start_session", "cmd": []string{"/bin/sh"}})
	if r.Type != "error" {
		t.Fatalf("start without auth: %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "create_session", "username": "prova"})
	if r.Type != "auth_message" {
		t.Fatalf("create %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "cancel_session"})
	if r.Type != "success" {
		t.Fatalf("cancel %+v", r)
	}
	r = call(t, conn, map[string]interface{}{"type": "start_session", "cmd": []string{"/bin/sh"}})
	if r.Type != "error" {
		t.Fatalf("start after cancel: %+v", r)
	}
}

func TestUnknownUser(t *testing.T) {
	_, conn := dial(t)
	r := call(t, conn, map[string]interface{}{"type": "create_session", "username": "nobody-here"})
	if r.Type != "error" {
		t.Fatalf("unknown user: %+v", r)
	}
}
