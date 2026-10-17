package config

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`[terminal]
vt = 1

# comment
[default_session]
command = "/usr/bin/singularity-greeter-client"
user = "greeter"

[initial_session]
command = "/usr/bin/atom-install-session"
user = "root"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VT != 1 || cfg.Default.Command != "/usr/bin/singularity-greeter-client" || cfg.Default.User != "greeter" {
		t.Fatalf("default %+v", cfg)
	}
	if cfg.Initial == nil || cfg.Initial.Command != "/usr/bin/atom-install-session" || cfg.Initial.User != "root" {
		t.Fatalf("initial %+v", cfg.Initial)
	}
}
