package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seed(t *testing.T, dir string, files ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrepareDelegatesTheUserSlice(t *testing.T) {
	Root = t.TempDir()
	files := []string{"cgroup.controllers", "cgroup.procs", "cgroup.threads", "cgroup.subtree_control", "cgroup.freeze"}
	seed(t, Root, files...)
	os.WriteFile(filepath.Join(Root, "cgroup.controllers"), []byte("cpuset cpu io memory pids"), 0o644)
	slice := filepath.Join(Root, "user.slice", fmt.Sprintf("user-%d.slice", os.Getuid()))
	seed(t, filepath.Join(Root, "user.slice"), files...)
	seed(t, slice, files...)
	seed(t, filepath.Join(slice, "session-4.scope"), files...)

	s, err := Prepare(os.Getuid(), os.Getgid(), "4")
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != filepath.Join(slice, "session-4.scope") || s.Slice != slice {
		t.Fatalf("unexpected paths %+v", s)
	}
	got, _ := os.ReadFile(filepath.Join(Root, "cgroup.subtree_control"))
	if !strings.Contains(string(got), "+") || strings.Contains(string(got), "cpuset") {
		t.Fatalf("subtree_control = %q", got)
	}
}

func TestThawAndReleaseTouchOnlyAppCgroups(t *testing.T) {
	Root = t.TempDir()
	slice := filepath.Join(Root, "user.slice", "user-1001.slice")
	app := filepath.Join(slice, "app-org.example.Editor.scope")
	other := filepath.Join(slice, "keep")
	seed(t, app, "cgroup.freeze")
	seed(t, other)
	os.WriteFile(filepath.Join(app, "cgroup.freeze"), []byte("1"), 0o644)

	s := &Session{Path: filepath.Join(slice, "session-4.scope"), Slice: slice}
	s.Thaw()
	if got, _ := os.ReadFile(filepath.Join(app, "cgroup.freeze")); string(got) != "0" {
		t.Fatalf("cgroup.freeze = %q", got)
	}
	os.Remove(filepath.Join(app, "cgroup.freeze"))
	s.Release()
	if _, err := os.Stat(app); !os.IsNotExist(err) {
		t.Fatal("empty app cgroup was not removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("non-app cgroup was removed")
	}
}
