// Package seat opens device nodes on behalf of a session and takes them away
// again when the session stops being in the foreground.
package seat

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	majorInput = 13
	majorDRM   = 226

	drmSetMaster  = 0x641e
	drmDropMaster = 0x641f
	eviocRevoke   = 0x40044591

	kdSetMode  = 0x4b3a
	kdText     = 0x00
	kdGraphics = 0x01
	vtActivate = 0x5606
)

// Device is one open device node.
type Device struct {
	Major, Minor uint32
	file         *os.File
	Paused       bool
}

// IsDRM reports whether the device is a DRM node.
func (d *Device) IsDRM() bool { return d.Major == majorDRM }

// Fd returns the descriptor handed to the session.
func (d *Device) Fd() int { return int(d.file.Fd()) }

// Allowed reports whether a session may ask for the device: graphics and
// input nodes only, as logind allows.
func Allowed(major, minor uint32) bool {
	return major == majorDRM || major == majorInput
}

// Node finds the device node for a character device number.
func Node(major, minor uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/dev/char/%d:%d/uevent", major, minor))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if name, ok := strings.CutPrefix(line, "DEVNAME="); ok && name != "" && !strings.Contains(name, "..") {
			return filepath.Join("/dev", name), nil
		}
	}
	return "", fmt.Errorf("device %d:%d has no node", major, minor)
}

// Open opens a device for a session. DRM nodes become master when the
// session is active.
func Open(major, minor uint32, active bool) (*Device, error) {
	if !Allowed(major, minor) {
		return nil, fmt.Errorf("device %d:%d is not a seat device", major, minor)
	}
	path, err := Node(major, minor)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != major || unix.Minor(uint64(st.Rdev)) != minor {
		return nil, fmt.Errorf("%s is not device %d:%d", path, major, minor)
	}
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	d := &Device{Major: major, Minor: minor, file: f}
	if d.IsDRM() {
		if active {
			ioctl(f.Fd(), drmSetMaster, 0)
		} else {
			ioctl(f.Fd(), drmDropMaster, 0)
			d.Paused = true
		}
	} else if !active {
		ioctl(f.Fd(), eviocRevoke, 0)
		d.Paused = true
	}
	return d, nil
}

// Pause takes the device away from the session: DRM drops master and input
// is revoked, so a background session can no longer read keystrokes.
func (d *Device) Pause() {
	if d.Paused {
		return
	}
	if d.IsDRM() {
		ioctl(d.file.Fd(), drmDropMaster, 0)
	} else {
		ioctl(d.file.Fd(), eviocRevoke, 0)
	}
	d.Paused = true
}

// Resume gives the device back. Revoked input cannot be reused, so input is
// reopened and the new descriptor replaces the old one.
func (d *Device) Resume() error {
	if !d.Paused {
		return nil
	}
	if d.IsDRM() {
		if err := ioctl(d.file.Fd(), drmSetMaster, 0); err != nil {
			return err
		}
		d.Paused = false
		return nil
	}
	fresh, err := Open(d.Major, d.Minor, true)
	if err != nil {
		return err
	}
	d.file.Close()
	d.file = fresh.file
	d.Paused = false
	return nil
}

// Close releases the device.
func (d *Device) Close() {
	if d.IsDRM() {
		ioctl(d.file.Fd(), drmDropMaster, 0)
	}
	d.file.Close()
}

func ioctl(fd uintptr, req, arg uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}

// Terminal manages the virtual terminal a graphical session runs on.
type Terminal struct {
	mu   sync.Mutex
	vt   int
	file *os.File
}

// Graphics switches the session terminal to graphics mode, so the kernel
// console does not draw over the session.
func (t *Terminal) Graphics(vt int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if vt <= 0 {
		return nil
	}
	if t.file != nil && t.vt == vt {
		return nil
	}
	f, err := os.OpenFile(fmt.Sprintf("/dev/tty%d", vt), os.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	if err := ioctl(f.Fd(), kdSetMode, kdGraphics); err != nil {
		f.Close()
		return err
	}
	if t.file != nil {
		t.file.Close()
	}
	t.file, t.vt = f, vt
	return nil
}

// Text gives the terminal back to the kernel console.
func (t *Terminal) Text() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return
	}
	ioctl(t.file.Fd(), kdSetMode, kdText)
	t.file.Close()
	t.file = nil
}

// Activate switches the foreground terminal.
func Activate(vt int) error {
	f, err := os.OpenFile("/dev/tty0", os.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return ioctl(f.Fd(), vtActivate, uintptr(vt))
}

// ActiveVT reads the foreground terminal number.
func ActiveVT() int {
	data, err := os.ReadFile("/sys/class/tty/tty0/active")
	if err != nil {
		return 0
	}
	var n int
	fmt.Sscanf(strings.TrimPrefix(strings.TrimSpace(string(data)), "tty"), "%d", &n)
	return n
}

// WatchVT calls changed whenever the foreground terminal changes.
func WatchVT(changed func(vt int)) error {
	f, err := os.Open("/sys/class/tty/tty0/active")
	if err != nil {
		return err
	}
	buf := make([]byte, 32)
	f.Read(buf)
	go func() {
		defer f.Close()
		for {
			fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLPRI | unix.POLLERR}}
			if _, err := unix.Poll(fds, -1); err != nil {
				if err == unix.EINTR {
					continue
				}
				return
			}
			f.Seek(0, 0)
			f.Read(buf)
			changed(ActiveVT())
		}
	}()
	return nil
}
