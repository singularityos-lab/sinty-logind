package login1

import (
	"os"
	"testing"
	"time"
)

func TestResolveFallsBackToTheUserSession(t *testing.T) {
	uid := uint32(os.Getuid())
	start := time.Now()
	s := &Service{sessions: map[string]*Session{
		"2": {ID: "2", UID: uid, Class: "user", Leader: -1, Started: start.Add(time.Minute)},
		"3": {ID: "3", UID: uid, Class: "user", Leader: -1, Started: start},
		"4": {ID: "4", UID: uid + 1, Class: "user", Leader: -1, Started: start},
	}}
	pid := uint32(os.Getpid())
	if sess := s.resolve(pid); sess == nil || sess.ID != "3" {
		t.Fatalf("without an active session got %+v, want the oldest session of the user", sess)
	}
	s.active = "2"
	if sess := s.resolve(pid); sess == nil || sess.ID != "2" {
		t.Fatalf("got %+v, want the active session", sess)
	}
	s.active = "4"
	if sess := s.resolve(pid); sess == nil || sess.ID != "3" {
		t.Fatalf("got %+v, want a session of the caller, not the active one of another user", sess)
	}
	delete(s.sessions, "2")
	delete(s.sessions, "3")
	if sess := s.resolve(pid); sess != nil {
		t.Fatalf("got %+v for a user without sessions", sess)
	}
}

func TestResolvePrefersTheSessionTree(t *testing.T) {
	uid := uint32(os.Getuid())
	s := &Service{active: "2", sessions: map[string]*Session{
		"2": {ID: "2", UID: uid, Class: "user", Leader: -1, Started: time.Now()},
		"5": {ID: "5", UID: uid, Class: "user", Leader: os.Getpid(), Started: time.Now()},
	}}
	if sess := s.resolve(uint32(os.Getpid())); sess == nil || sess.ID != "5" {
		t.Fatalf("got %+v, want the session whose leader is an ancestor", sess)
	}
}
