package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
)

const (
	dbFileName    = "scrutineer.db"
	dbFilePerm    = 0o600
	serverDialTTL = 500 * time.Millisecond
	sqliteMagic   = "SQLite format 3\x00"
)

// dispatch routes a subcommand when args[0] names one, returning handled=true.
// Server flags and an empty argv fall through with handled=false, except for
// the conventional --version/-version aliases. This preserves scrutineer's
// default behaviour (boot the server) for everything that is not a known
// command.
func dispatch(args []string, out io.Writer) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "backup":
		return true, runBackup(args[1:], out)
	case "restore":
		return true, runRestore(args[1:], out)
	case "proxy":
		return true, runProxy(args[1:])
	case "version", "--version", "-version":
		return true, runVersion(out)
	default:
		return false, nil
	}
}

// runBackup writes a consistent snapshot of data/scrutineer.db to -to (or a
// timestamped file in the working directory). It relies on VACUUM INTO, which
// cooperates with WAL, so it is safe to run while scrutineer is serving.
func runBackup(args []string, out io.Writer) error {
	fset := flag.NewFlagSet("backup", flag.ContinueOnError)
	var configPath, dataDir, to string
	fset.StringVar(&configPath, "config", "", "path to YAML config file (default: ./scrutineer.yaml if present)")
	fset.StringVar(&dataDir, "data", "", "data directory holding scrutineer.db (default: config value or ./data)")
	fset.StringVar(&to, "to", "", "backup destination file (default: ./scrutineer-backup-<timestamp>.db)")
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // usage already printed by Parse
		}
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(resolveDataDir(cfg, dataDir), dbFileName)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("no database at %s: %w", dbPath, err)
	}

	if to == "" {
		to = "scrutineer-backup-" + time.Now().Format("20060102-150405") + ".db"
	}
	if err := os.MkdirAll(filepath.Dir(to), dataPermSecure); err != nil {
		return err
	}
	if err := db.Snapshot(dbPath, to); err != nil {
		return err
	}
	// The snapshot carries the same operator-sensitive data as the live DB
	// (pre-disclosure findings, maintainer contacts, per-scan bearer tokens),
	// so keep it owner-only rather than at the umask default.
	if err := os.Chmod(to, dbFilePerm); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "backed up %s to %s\n", dbPath, to)
	return nil
}

// runRestore replaces data/scrutineer.db with the database at -from. It refuses
// to run while a server is reachable on the configured address and validates
// that -from is a SQLite file before touching the live database.
func runRestore(args []string, out io.Writer) error {
	fset := flag.NewFlagSet("restore", flag.ContinueOnError)
	var configPath, dataDir, addr, from string
	fset.StringVar(&configPath, "config", "", "path to YAML config file (default: ./scrutineer.yaml if present)")
	fset.StringVar(&dataDir, "data", "", "data directory holding scrutineer.db (default: config value or ./data)")
	fset.StringVar(&addr, "addr", "", "listen address checked to ensure no server is running (default: config value or 127.0.0.1:8080)")
	fset.StringVar(&from, "from", "", "backup file to restore (required)")
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // usage already printed by Parse
		}
		return err
	}
	if from == "" {
		return errors.New("restore: -from <file> is required")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if ok, err := isSQLiteFile(from); err != nil {
		return fmt.Errorf("read %s: %w", from, err)
	} else if !ok {
		return fmt.Errorf("%s is not a SQLite database", from)
	}
	if a := resolveAddr(cfg, addr); serverRunning(a) {
		return fmt.Errorf("a server is reachable on %s; stop scrutineer before restoring", a)
	}

	dir := resolveDataDir(cfg, dataDir)
	if err := os.MkdirAll(dir, dataPermSecure); err != nil {
		return err
	}
	dbPath := filepath.Join(dir, dbFileName)
	if err := installRestore(from, dbPath); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "restored %s to %s\n", from, dbPath)
	return nil
}

// installRestore copies src over the database at dbPath. It writes a temp file
// first, then removes the WAL sidecars, then renames into place, so the live
// name is never paired with a stale -wal/-shm: SQLite would otherwise replay
// the old frames onto the freshly restored file and corrupt it.
func installRestore(src, dbPath string) error {
	tmp := dbPath + ".restore-tmp"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			_ = os.Remove(tmp)
			return fmt.Errorf("remove %s: %w", dbPath+suffix, err)
		}
	}
	if err := os.Rename(tmp, dbPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install restored db: %w", err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, dbFilePerm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

// isSQLiteFile reports whether path begins with the SQLite file magic, so
// restore refuses to clobber the live database with a non-database file. A
// file too short to hold the 16-byte header is simply not a database.
func isSQLiteFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	hdr := make([]byte, len(sqliteMagic))
	if _, err := io.ReadFull(f, hdr); err != nil {
		return false, nil
	}
	return string(hdr) == sqliteMagic, nil
}

// serverRunning reports whether something accepts a TCP connection on addr.
// It is a best-effort guard: stopping the server is the real precondition for
// restore, and a server bound to a different address than the one resolved
// here will not be detected.
func serverRunning(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), serverDialTTL)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// resolveDataDir mirrors the server's precedence: an explicit flag wins over
// the config file's data key, which wins over the ./data default.
func resolveDataDir(cfg *config.Config, dataFlag string) string {
	if dataFlag != "" {
		return dataFlag
	}
	if cfg != nil && cfg.Data != "" {
		return cfg.Data
	}
	return "./data"
}

func resolveAddr(cfg *config.Config, addrFlag string) string {
	if addrFlag != "" {
		return addrFlag
	}
	if cfg != nil && cfg.Addr != "" {
		return cfg.Addr
	}
	return "127.0.0.1:8080"
}
