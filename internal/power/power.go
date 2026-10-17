// Package power turns the machine off when a power button is pressed.
package power

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	evKey    = 0x01
	keyPower = 116
)

func eviocgname(size uintptr) uintptr {
	return 0x80004506 | size<<16
}

func deviceName(f *os.File) string {
	buf := make([]byte, 256)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), eviocgname(uintptr(len(buf)-1)), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return ""
	}
	return string(bytes.TrimRight(buf, "\x00"))
}

// Watch scans for power button devices for a minute after start, as they can
// appear late during boot, and powers off on a key press.
func Watch(action func()) {
	var mu sync.Mutex
	watched := map[string]bool{}
	scan := func() {
		paths, _ := filepath.Glob("/dev/input/event*")
		for _, path := range paths {
			mu.Lock()
			seen := watched[path]
			mu.Unlock()
			if seen {
				continue
			}
			f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			if !strings.Contains(deviceName(f), "Power Button") {
				f.Close()
				continue
			}
			mu.Lock()
			watched[path] = true
			mu.Unlock()
			log.Printf("watching %s for the power button", path)
			go read(f, action)
		}
	}
	go func() {
		for i := 0; i < 12; i++ {
			scan()
			time.Sleep(5 * time.Second)
		}
	}()
}

func read(f *os.File, action func()) {
	defer f.Close()
	var ev struct {
		Sec, Usec int64
		Type      uint16
		Code      uint16
		Value     int32
	}
	for {
		if err := binary.Read(f, binary.NativeEndian, &ev); err != nil {
			return
		}
		if ev.Type == evKey && ev.Code == keyPower && ev.Value == 1 {
			action()
		}
	}
}

// PowerOff runs the system power off command.
func PowerOff() {
	log.Print("power button pressed, powering off")
	for _, c := range []string{"/bin/poweroff", "/sbin/poweroff"} {
		if exec.Command(c).Run() == nil {
			return
		}
	}
}
