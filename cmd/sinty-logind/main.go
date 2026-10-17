// Command sinty-logind manages logins, sessions and the seat on Sinty OS.
package main

import (
	"flag"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/singularityos-lab/sinty-accounts/accounts"

	"github.com/singularityos-lab/sinty-logind/internal/config"
	"github.com/singularityos-lab/sinty-logind/internal/greet"
	"github.com/singularityos-lab/sinty-logind/internal/login1"
	"github.com/singularityos-lab/sinty-logind/internal/power"
	"github.com/singularityos-lab/sinty-logind/internal/seatd"
)

const (
	socket     = "/run/sinty-logind/greet.sock"
	seatSocket = "/run/seatd.sock"
)

func main() {
	configPath := flag.String("config", config.Path, "greetd configuration file")
	noGreeter := flag.Bool("no-greeter", false, "serve login1 only, without running the greeter")
	serveAccounts := flag.Bool("accounts", true, "serve org.freedesktop.Accounts")
	interfaces := flag.String("account-interfaces", "/usr/share/accountsservice/interfaces", "directory of Accounts extension interface descriptions")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("sinty-logind: ")
	if os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") == "" {
		os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("reading %s: %v", *configPath, err)
	}
	var service *login1.Service
	for i := 0; ; i++ {
		service, err = login1.New(cfg.Default.User, cfg.VT)
		if err == nil {
			break
		}
		if i%10 == 0 {
			log.Printf("system bus not ready: %v", err)
		}
		time.Sleep(time.Second)
	}
	log.Print("serving org.freedesktop.login1")
	if *serveAccounts {
		serveUsers(service.Conn(), *interfaces)
	}
	gid := -1
	if g, err := user.LookupGroup("video"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if _, err := seatd.Listen(seatSocket, gid); err != nil {
		log.Printf("seat: %v", err)
	}
	power.Watch(power.PowerOff)
	if *noGreeter {
		select {}
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := greet.New(cfg, socket, service).Run(); err != nil {
		log.Fatal(err)
	}
}

// serveUsers publishes org.freedesktop.Accounts from this process, so the
// users and their sessions are answered by one daemon. A running
// accounts-daemon keeps the name and this one steps aside.
func serveUsers(conn *dbus.Conn, interfaces string) {
	svc := accounts.New(conn, accounts.Options{Root: "/", InterfacesDir: interfaces})
	if err := svc.Export(); err != nil {
		log.Printf("accounts: %v", err)
		return
	}
	reply, err := conn.RequestName(accounts.BusName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Printf("accounts: %s is owned by another process", accounts.BusName)
		return
	}
	go svc.Watch(make(chan struct{}))
	log.Print("serving org.freedesktop.Accounts")
}
