# sinty-logind

The login, session and seat manager of SintyOS. One root daemon does what
greetd, seatd, systemd-logind and accounts-daemon do on other systems: it runs the login
screen, authenticates users through PAM, starts their sessions, hands the
graphics and input devices to the compositor and answers on
`org.freedesktop.login1` for power, sessions and the seat.

## Why it exists

SintyOS does not boot with systemd. PID 1 is `sinit` and services are driven by
`atomctl`. The login chain used to be three separate programs: seatd for the
devices, greetd for the login and a small login1 shim for the power buttons.
Each started on its own, with its own idea of who was logged in, and every
hand-off between them was a place where the boot could stall between the
splash and the login screen.

`sinty-logind` keeps a single view of the seat and its sessions, so the
compositor, the greeter and the desktop all ask the same process.

## What it implements

- **The greetd protocol.** Greeters written for greetd connect to
  `$GREETD_SOCK` and use `create_session`, `post_auth_message_response`,
  `start_session` and `cancel_session` unchanged. Authentication and session
  setup use the `greetd` PAM service. The configuration is greetd's own
  `/etc/greetd/config.toml` (`[terminal]`, `[default_session]`,
  `[initial_session]`).
- **The seatd protocol** on `/run/seatd.sock`, so compositors using libseat
  open DRM, input and hidraw devices through it. The seat is bound to the
  virtual terminal like seatd's: devices are revoked when the terminal is
  switched away and given back when it returns.
- **`org.freedesktop.login1`.** Power actions (`Reboot`, `PowerOff`,
  `Suspend`, `Can*`), `Inhibit` locks honoured before sleep, sessions and
  `seat0` with `GetSession`, `GetSessionByPID` and `ListSessions`, and the
  session methods `TakeControl`, `TakeDevice`, `ReleaseDevice`, `Activate`,
  `Terminate`, `Lock`, `Unlock` and `SetBrightness`.
- **The power button**, which turns the machine off.
- **`org.freedesktop.Accounts`**, the users and their settings, served from
  this process by the [sinty-accounts](https://github.com/singularityos-lab/sinty-accounts)
  package, so one daemon answers for users and their sessions.

Callers are authorized by uid: power actions are open to root, human users
and the greeter; session methods to the session's own user and root.

## Build

    make build            # ./sinty-logind
    make test
    go build ./...        # plain build

Requires Go >= 1.25, Linux and Linux-PAM (the PAM binding uses cgo). The
non-stdlib dependencies are `github.com/godbus/dbus/v5` and
`golang.org/x/sys/unix`.
