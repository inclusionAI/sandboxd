// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessUserScriptCleanupOwnership(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	script, err := filepath.Abs("../process-user.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	stubs := map[string]string{
		"chown":              "#!/bin/sh\nexit 0\n",
		"jq":                 "#!/bin/sh\ncat >/dev/null\n",
		"checkpoint-restore": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALLS\"\n",
		"sbox": `#!/bin/bash
printf '%s\n' "$*" >> "$STARTS"
if [[ " $* " == *" inspect "* ]]; then echo '{}'; exit 0; fi
id= stdout=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --sandbox-id) id=$2; shift ;;
        --stdout) stdout=$2; shift ;;
    esac
    shift
done
if [ "$ALLOW_DEFAULT" = 1 ] && [[ "$id" == *-default ]]; then
    printf '0:0\n' > "$stdout"
    exit 0
fi
exit 1
`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string, exists, allowDefault bool) (string, string) {
		t.Helper()
		dir := filepath.Join(fixture, name)
		if exists {
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
		}
		calls, starts := dir+".calls", dir+".starts"
		command := exec.Command(bash, script)
		allow := "0"
		if allowDefault {
			allow = "1"
		}
		command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_DIR="+dir, "ROOTFS=/unused", "SANDBOXD_USER_TEST_PREFIX=cleanup-test", "CALLS="+calls, "STARTS="+starts, "ALLOW_DEFAULT="+allow)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("expected fixture failure, output: %s", output)
		}
		deleted, _ := os.ReadFile(calls)
		started, _ := os.ReadFile(starts)
		return string(deleted), string(started)
	}
	if deleted, started := run("existing", true, false); deleted != "" || started != "" {
		t.Fatalf("existing directory triggered sandbox calls: %s %s", deleted, started)
	}
	deleted, first := run("failed-first", false, false)
	if deleted != "" {
		t.Fatalf("failed start was cleaned as an owned sandbox: %s", deleted)
	}
	deleted, second := run("failed-second", false, false)
	if deleted != "" || first == second {
		t.Fatalf("runs reused an ID or deleted an unowned sandbox: %s %s %s", deleted, first, second)
	}
	deleted, _ = run("one-owned", false, true)
	if deleted == "" {
		t.Fatal("owned sandbox was not cleaned")
	}
	for _, call := range strings.Split(strings.TrimSpace(deleted), "\n") {
		if !strings.HasSuffix(call, "-default") {
			t.Fatalf("cleanup deleted an unowned sandbox: %s", call)
		}
	}
}
