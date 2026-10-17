DAEMON := sinty-logind
PREFIX ?= /usr

.PHONY: all build test vet install clean

all: build

build:
	go build -o $(DAEMON) ./cmd/sinty-logind

test:
	go test ./...

vet:
	go vet ./...

install: build
	install -Dm755 $(DAEMON) $(DESTDIR)$(PREFIX)/libexec/$(DAEMON)
	install -Dm644 packaging/sinty-logind.service $(DESTDIR)$(PREFIX)/lib/systemd/system/sinty-logind.service
	install -Dm644 packaging/org.freedesktop.login1.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/org.freedesktop.login1.conf

clean:
	rm -f $(DAEMON)
