// Package cgroup gives each user session its own cgroup v2 subtree, delegated
// to the user, so the session can place, measure and freeze its applications.
package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Root is the cgroup v2 mount point; tests point it elsewhere.
var Root = "/sys/fs/cgroup"

var controllers = []string{"cpu", "memory", "io", "pids"}

var delegated = []string{"cgroup.procs", "cgroup.threads", "cgroup.subtree_control"}

// Session is the cgroup a session leader starts in.
type Session struct {
	// Path is the session scope, the cgroup the leader is cloned into.
	Path string
	// Slice is the user's delegated slice that holds the session and its apps.
	Slice string
}

// Prepare creates user.slice/user-UID.slice/session-ID.scope, enables the
// available controllers along the way and hands the user slice to uid.
func Prepare(uid, gid int, id string) (*Session, error) {
	if _, err := os.Stat(filepath.Join(Root, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("cgroup v2 not mounted: %w", err)
	}
	users := filepath.Join(Root, "user.slice")
	slice := filepath.Join(users, fmt.Sprintf("user-%d.slice", uid))
	scope := filepath.Join(slice, "session-"+id+".scope")
	for _, dir := range []string{users, slice, scope} {
		if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	for _, dir := range []string{Root, users, slice} {
		enable(dir)
	}
	for _, dir := range []string{slice, scope} {
		if err := os.Chown(dir, uid, gid); err != nil {
			return nil, err
		}
		for _, f := range delegated {
			if err := os.Chown(filepath.Join(dir, f), uid, gid); err != nil {
				return nil, err
			}
		}
	}
	return &Session{Path: scope, Slice: slice}, nil
}

func enable(dir string) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return
	}
	available := strings.Fields(string(data))
	for _, c := range controllers {
		for _, a := range available {
			if a == c {
				os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+"+c), 0)
			}
		}
	}
}

// Thaw resumes every app the session paused, so the processes can receive the
// signals that end the session.
func (s *Session) Thaw() {
	for _, dir := range s.apps() {
		os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("0"), 0)
	}
}

// Release removes the session scope and the app cgroups the session left in
// the user slice once they are empty. Cgroups that still hold processes stay.
func (s *Session) Release() {
	os.Remove(s.Path)
	for _, dir := range s.apps() {
		os.Remove(dir)
	}
	os.Remove(s.Slice)
}

func (s *Session) apps() []string {
	entries, err := os.ReadDir(s.Slice)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "app-") {
			dirs = append(dirs, filepath.Join(s.Slice, e.Name()))
		}
	}
	return dirs
}
