// Command migrate-sqlite-to-postgres copies a scrutineer SQLite database into
// a PostgreSQL server so an operator can switch the `database` backend in
// scrutineer.yaml without losing history.
//
// Usage:
//
//	go run ./scripts/migrate-sqlite-to-postgres \
//	    -sqlite ./data/scrutineer.db \
//	    -postgres 'postgres://scrutineer:secret@localhost:5432/scrutineer?sslmode=disable'
//
// It reuses the application's GORM models and db.OpenBackend, so the target
// schema is created exactly as the server would create it (including the
// two-pass migration that resolves the scans<->findings foreign-key cycle),
// and SQLite's text-encoded timestamps/booleans/blobs are converted through
// their Go types rather than copied as raw strings.
//
// The whole copy runs in one transaction with session_replication_role set to
// 'replica', which suspends foreign-key and trigger enforcement for the load.
// That sidesteps insert-ordering entirely (again, the scans<->findings cycle)
// and is the standard bulk-import approach; it requires a superuser or
// equivalent (rds_superuser on managed Postgres). After the copy, per-table id
// sequences are advanced past the imported rows.
//
// The target must be empty (no repositories) unless -force is given. The
// SQLite source is opened the same way the server opens it, which brings it up
// to the current schema before copying — run against a copy if you would
// rather not touch the live file.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
)

const batchSize = 200

func main() {
	var sqlitePath, pgDSN string
	var force bool
	flag.StringVar(&sqlitePath, "sqlite", "./data/scrutineer.db", "path to the source SQLite database")
	flag.StringVar(&pgDSN, "postgres", "", "destination PostgreSQL DSN (required)")
	flag.BoolVar(&force, "force", false, "copy even if the destination already has data (rows are added, not replaced)")
	flag.Parse()

	if err := run(sqlitePath, pgDSN, force); err != nil {
		log.Fatalf("migrate: %v", err)
	}
}

func run(sqlitePath, pgDSN string, force bool) error {
	if pgDSN == "" {
		return fmt.Errorf("-postgres DSN is required")
	}
	if _, err := os.Stat(sqlitePath); err != nil {
		return fmt.Errorf("source database %s: %w", sqlitePath, err)
	}

	src, err := db.Open(sqlitePath)
	if err != nil {
		return fmt.Errorf("open sqlite source: %w", err)
	}
	dst, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: pgDSN})
	if err != nil {
		return fmt.Errorf("open postgres destination: %w", err)
	}

	if !force {
		var repos int64
		if err := dst.Model(&db.Repository{}).Count(&repos).Error; err != nil {
			return fmt.Errorf("check destination: %w", err)
		}
		if repos > 0 {
			return fmt.Errorf("destination already has %d repositories; refusing without -force", repos)
		}
	}

	// copiers copy the typed models in an order that reads parents before
	// children (irrelevant for FK enforcement while it is suspended, but it
	// keeps the log readable). Each entry resolves its own table name.
	copiers := []func(src, tx *gorm.DB) (string, int64, error){
		copyModel[db.Repository], copyModel[db.Scan], copyModel[db.Finding],
		copyModel[db.FindingLabel], copyModel[db.FindingNote], copyModel[db.FindingCommunication],
		copyModel[db.FindingReference], copyModel[db.FindingHistory], copyModel[db.FindingReview],
		copyModel[db.Dependency], copyModel[db.Package], copyModel[db.Dependent],
		copyModel[db.FindingDependent], copyModel[db.Advisory], copyModel[db.Maintainer],
		copyModel[db.Skill], copyModel[db.Subproject], copyModel[db.SBOMUpload],
		copyModel[db.SBOMPackage], copyModel[db.CNA], copyModel[db.Setting],
	}
	// joinTables have no model struct (pure many-to-many link rows). They hold
	// only integer foreign keys, so a generic row copy is safe.
	joinTables := []string{"repository_maintainers", "finding_labels_join"}

	if err := warnUnhandledTables(src, dst, copiers, joinTables); err != nil {
		return err
	}

	handled := make([]string, 0, len(copiers))
	err = dst.Transaction(func(tx *gorm.DB) error {
		// Suspend FK/trigger enforcement for this transaction so insert order
		// and the scans<->findings cycle do not matter.
		if err := tx.Exec("SET LOCAL session_replication_role = replica").Error; err != nil {
			return fmt.Errorf("disable fk enforcement: %w", err)
		}
		for _, c := range copiers {
			table, n, err := c(src, tx)
			if err != nil {
				return fmt.Errorf("copy %s: %w", table, err)
			}
			handled = append(handled, table)
			log.Printf("copied %-24s %6d rows", table, n)
		}
		for _, jt := range joinTables {
			n, err := copyRaw(src, tx, jt)
			if err != nil {
				return fmt.Errorf("copy %s: %w", jt, err)
			}
			log.Printf("copied %-24s %6d rows", jt, n)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Sequences were not touched while rows were inserted with explicit ids, so
	// advance each id sequence past the imported maximum.
	for _, table := range handled {
		if err := resetSequence(dst, table); err != nil {
			return fmt.Errorf("reset sequence for %s: %w", table, err)
		}
	}

	log.Printf("done. Set `database: {driver: postgres, dsn: ...}` in scrutineer.yaml to use the migrated data.")
	return nil
}

// copyModel streams every row of model T from src into tx in batches, reading
// through the Go types so SQLite's text/int encodings become the destination's
// native column types. Associations are omitted so each table is copied exactly
// once (children are copied by their own entry, not cascaded from the parent).
func copyModel[T any](src, tx *gorm.DB) (string, int64, error) {
	table := tableName(tx, new(T))
	var total int64
	var batch []T
	res := src.Model(new(T)).FindInBatches(&batch, batchSize, func(_ *gorm.DB, _ int) error {
		if len(batch) == 0 {
			return nil
		}
		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Omit(clause.Associations).
			CreateInBatches(batch, batchSize).Error; err != nil {
			return err
		}
		total += int64(len(batch))
		return nil
	})
	return table, total, res.Error
}

// copyRaw copies a table generically as untyped rows. Used for the many-to-many
// join tables, which have no model and carry only integer foreign keys.
func copyRaw(src, tx *gorm.DB, table string) (int64, error) {
	var rows []map[string]any
	if err := src.Table(table).Find(&rows).Error; err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if err := tx.Table(table).CreateInBatches(rows, batchSize).Error; err != nil {
		return 0, err
	}
	return int64(len(rows)), nil
}

// resetSequence advances table's id sequence past the largest imported id so
// future inserts do not collide. Tables without an id serial (e.g. settings,
// keyed by a string) have no such sequence and are skipped — pg_get_serial_sequence
// errors rather than returns null for a missing column, so the id column is
// checked first.
func resetSequence(dst *gorm.DB, table string) error {
	var hasID bool
	if err := dst.Raw(
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = ? AND column_name = 'id')`,
		table).Scan(&hasID).Error; err != nil {
		return err
	}
	if !hasID {
		return nil
	}
	var seq sql.NullString
	if err := dst.Raw("SELECT pg_get_serial_sequence(?, 'id')", table).Scan(&seq).Error; err != nil {
		return err
	}
	if !seq.Valid || seq.String == "" {
		return nil
	}
	// is_called is true only when rows exist, so an empty table leaves the
	// sequence delivering 1 on the first insert.
	q := fmt.Sprintf(
		`SELECT setval(?, COALESCE((SELECT MAX(id) FROM %q), 1), (SELECT MAX(id) FROM %q) IS NOT NULL)`,
		table, table)
	return dst.Exec(q, seq.String).Error
}

// warnUnhandledTables fails loudly if the source holds a table this migrator
// neither copies nor knowingly skips, so a future schema addition cannot be
// dropped silently. goqite (transient job queue) and SQLite internals are
// expected skips.
func warnUnhandledTables(src, dst *gorm.DB, copiers []func(src, tx *gorm.DB) (string, int64, error), joinTables []string) error {
	known := map[string]bool{"goqite": true}
	for _, jt := range joinTables {
		known[jt] = true
	}
	// Resolve each model's table name via the destination naming strategy.
	for _, name := range modelTableNames(dst) {
		known[name] = true
	}

	var names []string
	if err := src.Raw(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&names).Error; err != nil {
		return fmt.Errorf("list source tables: %w", err)
	}
	var unknown []string
	for _, n := range names {
		if !known[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("source has tables this migrator does not handle: %v; update the script before migrating", unknown)
	}
	_ = copiers
	return nil
}

// modelTableNames returns the destination table name for every copied model,
// kept in sync with the copiers list above.
func modelTableNames(g *gorm.DB) []string {
	models := []any{
		&db.Repository{}, &db.Scan{}, &db.Finding{},
		&db.FindingLabel{}, &db.FindingNote{}, &db.FindingCommunication{},
		&db.FindingReference{}, &db.FindingHistory{}, &db.FindingReview{},
		&db.Dependency{}, &db.Package{}, &db.Dependent{},
		&db.FindingDependent{}, &db.Advisory{}, &db.Maintainer{},
		&db.Skill{}, &db.Subproject{}, &db.SBOMUpload{},
		&db.SBOMPackage{}, &db.CNA{}, &db.Setting{},
	}
	names := make([]string, 0, len(models))
	for _, m := range models {
		names = append(names, tableName(g, m))
	}
	return names
}

// tableName resolves the table a model maps to under g's naming strategy.
func tableName(g *gorm.DB, model any) string {
	stmt := &gorm.Statement{DB: g}
	if err := stmt.Parse(model); err != nil {
		return fmt.Sprintf("%T", model)
	}
	return stmt.Schema.Table
}
