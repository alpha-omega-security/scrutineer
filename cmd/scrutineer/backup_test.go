package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func makeProbeDB(t *testing.T, path string) {
	t.Helper()
	gdb, err := db.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := gdb.Exec("CREATE TABLE probe(v INTEGER)").Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec("INSERT INTO probe(v) VALUES (4242)").Error; err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqldb.Close(); err != nil {
		t.Fatal(err)
	}
}

func readProbe(t *testing.T, path string) int {
	t.Helper()
	gdb, err := db.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		if sqldb, err := gdb.DB(); err == nil {
			_ = sqldb.Close()
		}
	}()
	var v int
	if err := gdb.Raw("SELECT v FROM probe").Scan(&v).Error; err != nil {
		t.Fatalf("read probe from %s: %v", path, err)
	}
	return v
}

// freeAddr returns a loopback address with nothing listening on it, so the
// restore server-running guard sees no server.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestRunBackup_roundTrip(t *testing.T) {
	dataDir := t.TempDir()
	makeProbeDB(t, filepath.Join(dataDir, "scrutineer.db"))
	dest := filepath.Join(t.TempDir(), "backup.db")

	var out bytes.Buffer
	if err := runBackup([]string{"-data", dataDir, "-to", dest}, &out); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	if v := readProbe(t, dest); v != 4242 {
		t.Errorf("restored probe = %d, want 4242", v)
	}
	if info, err := os.Stat(dest); err != nil {
		t.Fatalf("stat dest: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("dest perms = %o, want 600", perm)
	}
	if !strings.Contains(out.String(), dest) {
		t.Errorf("output %q does not name the destination", out.String())
	}
}

func TestRunBackup_defaultDest(t *testing.T) {
	t.Chdir(t.TempDir())
	dataDir := t.TempDir()
	makeProbeDB(t, filepath.Join(dataDir, "scrutineer.db"))

	if err := runBackup([]string{"-data", dataDir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	matches, err := filepath.Glob("scrutineer-backup-*.db")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("default-dest glob = %v, want exactly one file", matches)
	}
	if v := readProbe(t, matches[0]); v != 4242 {
		t.Errorf("default-dest probe = %d, want 4242", v)
	}
}

func TestRunBackup_missingSource(t *testing.T) {
	err := runBackup([]string{"-data", t.TempDir(), "-to", filepath.Join(t.TempDir(), "b.db")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatalf("err = %v, want 'no database'", err)
	}
}

func TestRunBackup_destExists(t *testing.T) {
	dataDir := t.TempDir()
	makeProbeDB(t, filepath.Join(dataDir, "scrutineer.db"))
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := os.WriteFile(dest, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runBackup([]string{"-data", dataDir, "-to", dest}, &bytes.Buffer{}); err == nil {
		t.Fatal("backup over an existing destination should fail")
	}
}

func TestRunRestore_roundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "scrutineer.db")
	makeProbeDB(t, src)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Snapshot(src, backup); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "scrutineer.db")
	// A stale main file plus WAL sidecars from a prior DB must all be replaced
	// or removed; a surviving -wal would corrupt the restored file on reopen.
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.WriteFile(f, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := runRestore([]string{"-data", dataDir, "-addr", freeAddr(t), "-from", backup}, &bytes.Buffer{}); err != nil {
		t.Fatalf("runRestore: %v", err)
	}
	if v := readProbe(t, dbPath); v != 4242 {
		t.Errorf("restored probe = %d, want 4242", v)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); !os.IsNotExist(err) {
			t.Errorf("%s%s still present after restore (err=%v)", dbPath, suffix, err)
		}
	}
}

func TestRunRestore_serverRunning(t *testing.T) {
	src := filepath.Join(t.TempDir(), "scrutineer.db")
	makeProbeDB(t, src)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Snapshot(src, backup); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	err = runRestore([]string{"-data", t.TempDir(), "-addr", l.Addr().String(), "-from", backup}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "reachable") {
		t.Fatalf("err = %v, want a 'reachable' refusal", err)
	}
}

func TestRunRestore_missingFrom(t *testing.T) {
	err := runRestore([]string{"-data", t.TempDir()}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "-from") {
		t.Fatalf("err = %v, want '-from' required", err)
	}
}

func TestRunRestore_notSQLite(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "notdb.txt")
	if err := os.WriteFile(bad, []byte("this is not a sqlite database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runRestore([]string{"-data", t.TempDir(), "-addr", freeAddr(t), "-from", bad}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not a SQLite") {
		t.Fatalf("err = %v, want 'not a SQLite database'", err)
	}
}

func TestDispatch(t *testing.T) {
	if handled, _ := dispatch(nil, &bytes.Buffer{}); handled {
		t.Error("empty argv should fall through to the server")
	}
	if handled, _ := dispatch([]string{"-data", "x"}, &bytes.Buffer{}); handled {
		t.Error("a server flag should fall through to the server")
	}
	if handled, _ := dispatch([]string{"serve"}, &bytes.Buffer{}); handled {
		t.Error("an unknown word should fall through to the server")
	}
	// Known subcommands are handled even when they then error.
	if handled, err := dispatch([]string{"restore"}, &bytes.Buffer{}); !handled || err == nil {
		t.Errorf("restore: handled=%v err=%v, want handled with an error", handled, err)
	}
	if handled, err := dispatch([]string{"backup", "-data", t.TempDir()}, &bytes.Buffer{}); !handled || err == nil {
		t.Errorf("backup: handled=%v err=%v, want handled with an error", handled, err)
	}
}
