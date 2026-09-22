// Command migrate-sqlite-to-postgres copies a stopped instance's SQLite database
// into an empty PostgreSQL database.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"scrutineer/internal/db"
)

const batchSize = 200
const schemaVersionKey = "database_schema_version"

type repositoryMaintainer struct {
	RepositoryID uint `gorm:"primaryKey"`
	MaintainerID uint `gorm:"primaryKey"`
}

func (repositoryMaintainer) TableName() string { return "repository_maintainers" }

type findingLabel struct {
	FindingID      uint `gorm:"primaryKey"`
	FindingLabelID uint `gorm:"primaryKey"`
}

func (findingLabel) TableName() string { return "finding_labels_join" }

func migrationModels() []any {
	return []any{
		&db.Repository{}, &db.Scan{}, &db.Finding{},
		&db.FindingLabel{}, &db.FindingNote{}, &db.FindingCommunication{},
		&db.FindingReference{}, &db.FindingHistory{}, &db.FindingReview{},
		&db.FindingVerification{}, &db.FindingAttackPath{},
		&db.RemediationAttempt{}, &db.RemediationValidation{}, &db.AuditEvent{},
		&db.Dependency{}, &db.ExpectedFinding{}, &db.Package{}, &db.PackageAlternative{},
		&db.Dependent{}, &db.FindingDependent{}, &db.Advisory{}, &db.AdvisoryAudit{},
		&db.Maintainer{}, &db.Skill{}, &db.Subproject{}, &db.ComplianceControl{},
		&db.SBOMUpload{}, &db.SBOMPackage{}, &db.CNA{}, &db.Setting{},
		&db.Conversation{}, &db.ChatMessage{}, &db.InterchangeRecord{},
		&repositoryMaintainer{}, &findingLabel{},
	}
}

func main() {
	var sqlitePath, pgDSN string
	flag.StringVar(&sqlitePath, "sqlite", "./data/scrutineer.db", "path to the source SQLite database")
	flag.StringVar(&pgDSN, "postgres", "", "destination PostgreSQL DSN (required)")
	flag.Parse()
	if err := run(sqlitePath, pgDSN); err != nil {
		log.Fatalf("migrate: %v", err)
	}
}

func run(sqlitePath, pgDSN string) error {
	if pgDSN == "" {
		return fmt.Errorf("-postgres DSN is required")
	}
	info, err := os.Stat(sqlitePath)
	if err != nil {
		return fmt.Errorf("source database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source database must be a regular file")
	}
	dir, err := os.MkdirTemp("", "scrutineer-migrate-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	snapshot := filepath.Join(dir, "source.db")
	log.Print("snapshotting SQLite source; keep both instances stopped until migration finishes")
	if err := db.Snapshot(sqlitePath, snapshot); err != nil {
		return fmt.Errorf("snapshot source: %w", err)
	}
	src, err := db.Connect(snapshot)
	if err != nil {
		return fmt.Errorf("open source snapshot: %w", err)
	}
	defer closeDB(src)
	tables, err := migrationTables(src)
	if err != nil {
		return err
	}
	if err := checkSource(src, tables); err != nil {
		return err
	}
	dst, err := openDestination(pgDSN)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer closeDB(dst)
	if err := dst.Transaction(func(tx *gorm.DB) error {
		return migrate(src, tx, tables)
	}); err != nil {
		return err
	}
	log.Print("migration complete; set database.driver to postgres and database.dsn before restarting Scrutineer")
	return nil
}

func closeDB(gdb *gorm.DB) {
	if conn, err := gdb.DB(); err == nil {
		_ = conn.Close()
	}
}

func openDestination(dsn string) (*gorm.DB, error) {
	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	defer closeDB(connection)
	// Check before AutoMigrate can alter an existing instance's schema or data.
	if err := checkDestination(connection); err != nil {
		return nil, err
	}
	return db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: dsn})
}

func checkDestination(tx *gorm.DB) error {
	var tables []string
	if err := tx.Raw("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()").Scan(&tables).Error; err != nil {
		return err
	}
	for _, table := range tables {
		query := tx.Table(pgx.Identifier{table}.Sanitize())
		if table == "settings" {
			query = query.Where("key <> ?", schemaVersionKey)
		}
		var exists bool
		if err := tx.Raw("SELECT EXISTS (?)", query.Select("1")).Scan(&exists).Error; err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("destination table %s is not empty; use an empty database", table)
		}
	}
	return nil
}

func migrationTables(src *gorm.DB) ([]*schema.Schema, error) {
	var tables []*schema.Schema
	for _, model := range migrationModels() {
		stmt := &gorm.Statement{DB: src}
		if err := stmt.Parse(model); err != nil {
			return nil, err
		}
		tables = append(tables, stmt.Schema)
	}
	return tables, nil
}

func checkSource(src *gorm.DB, tables []*schema.Schema) error {
	known := map[string]bool{"sqlite_sequence": true, "goqite": true}
	for _, table := range tables {
		known[table.Table] = true
		if !src.Migrator().HasTable(table.Table) {
			return fmt.Errorf("source is missing table %s; upgrade the SQLite instance to this Scrutineer revision before migrating", table.Table)
		}
		columns, err := src.Migrator().ColumnTypes(table.Table)
		if err != nil {
			return err
		}
		present := make(map[string]bool, len(columns))
		for _, column := range columns {
			present[column.Name()] = true
			if table.FieldsByDBName[column.Name()] == nil {
				return fmt.Errorf("source column %s.%s is not handled by this migrator", table.Table, column.Name())
			}
		}
		for _, column := range table.DBNames {
			if !present[column] {
				return fmt.Errorf("source is missing column %s.%s; upgrade the SQLite instance to this Scrutineer revision before migrating", table.Table, column)
			}
		}
	}
	var names []string
	if err := src.Raw("SELECT name FROM sqlite_master WHERE type = 'table'").Scan(&names).Error; err != nil {
		return err
	}
	for _, name := range names {
		if !known[name] && !strings.HasPrefix(name, "sqlite_") {
			return fmt.Errorf("source table %s is not handled by this migrator", name)
		}
	}
	var pending int64
	if err := src.Model(&db.Scan{}).Where("LOWER(status) IN ?", []string{"queued", "running"}).Count(&pending).Error; err != nil {
		return err
	}
	if pending != 0 {
		return fmt.Errorf("source has %d queued/running scans; finish or cancel them before migrating", pending)
	}
	if src.Migrator().HasTable("goqite") {
		if err := src.Table("goqite").Count(&pending).Error; err != nil {
			return err
		}
		if pending != 0 {
			return fmt.Errorf("source job queue contains %d messages; drain it before migrating", pending)
		}
	}
	return nil
}

func migrate(src, tx *gorm.DB, tables []*schema.Schema) error {
	var namespace string
	if err := tx.Raw("SELECT current_schema()").Scan(&namespace).Error; err != nil {
		return err
	}
	names := make([]string, 0, len(tables))
	for _, table := range tables {
		names = append(names, pgx.Identifier{namespace, table.Table}.Sanitize())
	}
	if err := tx.Exec("LOCK TABLE " + strings.Join(names, ", ") + " IN ACCESS EXCLUSIVE MODE").Error; err != nil {
		return err
	}
	if err := checkDestination(tx); err != nil {
		return err
	}
	constraints, err := deferConstraints(tx, namespace, tables)
	if err != nil {
		return err
	}
	for _, table := range tables {
		count, err := copyTable(src, tx, table)
		if err != nil {
			return fmt.Errorf("copy %s: %w", table.Table, err)
		}
		log.Printf("copied %-26s %d rows", table.Table, count)
	}
	if err := tx.Exec("SET CONSTRAINTS ALL IMMEDIATE").Error; err != nil {
		return fmt.Errorf("validate migrated relationships: %w", err)
	}
	for _, constraint := range constraints {
		if err := tx.Exec(constraint.restoreSQL(namespace)).Error; err != nil {
			return err
		}
	}
	for _, table := range tables {
		if table.FieldsByDBName["id"] != nil {
			if err := resetSequence(tx, namespace, table.Table); err != nil {
				return fmt.Errorf("reset sequence for %s: %w", table.Table, err)
			}
		}
	}
	return nil
}

type foreignKey struct {
	TableName  string
	Name       string
	Deferrable bool
	Deferred   bool
}

func (key foreignKey) alterSQL(namespace string) string {
	return "ALTER TABLE " + pgx.Identifier{namespace, key.TableName}.Sanitize() +
		" ALTER CONSTRAINT " + pgx.Identifier{key.Name}.Sanitize()
}

func (key foreignKey) restoreSQL(namespace string) string {
	mode := " NOT DEFERRABLE INITIALLY IMMEDIATE"
	if key.Deferrable {
		mode = " DEFERRABLE INITIALLY IMMEDIATE"
		if key.Deferred {
			mode = " DEFERRABLE INITIALLY DEFERRED"
		}
	}
	return key.alterSQL(namespace) + mode
}

func deferConstraints(tx *gorm.DB, namespace string, tables []*schema.Schema) ([]foreignKey, error) {
	names := make([]string, 0, len(tables))
	for _, table := range tables {
		names = append(names, table.Table)
	}
	var keys []foreignKey
	if err := tx.Raw(`SELECT r.relname AS table_name, c.conname AS name,
		c.condeferrable AS deferrable, c.condeferred AS deferred
		FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = r.relnamespace
		WHERE c.contype = 'f' AND n.nspname = ? AND r.relname IN ?`, namespace, names).Scan(&keys).Error; err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := tx.Exec(key.alterSQL(namespace) + " DEFERRABLE INITIALLY IMMEDIATE").Error; err != nil {
			return nil, err
		}
	}
	if err := tx.Exec("SET CONSTRAINTS ALL DEFERRED").Error; err != nil {
		return nil, err
	}
	return keys, nil
}

func copyTable(src, tx *gorm.DB, table *schema.Schema) (int64, error) {
	query := src.Table(table.Table)
	if table.Table == "settings" {
		query = query.Where("key <> ?", schemaVersionKey)
	}
	rows, err := query.Rows()
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	batch := make([]map[string]any, 0, batchSize)
	var total, cleaned int64
	for rows.Next() {
		record, changed, err := readRow(src, rows, columns, table)
		if err != nil {
			return total, err
		}
		if changed {
			cleaned++
		}
		batch = append(batch, record)
		total++
		if len(batch) == batchSize {
			if err := tx.Table(table.Table).Create(&batch).Error; err != nil {
				return total, err
			}
			batch = make([]map[string]any, 0, batchSize)
		}
	}
	if err := rows.Err(); err != nil {
		return total, err
	}
	if len(batch) != 0 {
		if err := tx.Table(table.Table).Create(&batch).Error; err != nil {
			return total, err
		}
	}
	if cleaned != 0 {
		log.Printf("removed NUL bytes or replaced invalid UTF-8 in %d %s rows", cleaned, table.Table)
	}
	return total, nil
}

func readRow(src *gorm.DB, rows *sql.Rows, columns []string, table *schema.Schema) (map[string]any, bool, error) {
	record := reflect.New(table.ModelType)
	if err := src.ScanRows(rows, record.Interface()); err != nil {
		return nil, false, err
	}
	// Preserve SQL NULLs and zero values instead of applying GORM create defaults.
	raw := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range raw {
		pointers[i] = &raw[i]
	}
	if err := rows.Scan(pointers...); err != nil {
		return nil, false, err
	}
	values := make(map[string]any, len(columns))
	changed := false
	for i, column := range columns {
		if raw[i] == nil {
			values[column] = nil
			continue
		}
		value, _ := table.FieldsByDBName[column].ValueOf(context.Background(), record)
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Pointer {
			rv = rv.Elem()
		}
		if rv.Kind() == reflect.String {
			text := rv.String()
			clean := db.SanitizePGText(text)
			changed = changed || clean != text
			value = clean
		}
		values[column] = value
	}
	return values, changed, nil
}

func resetSequence(tx *gorm.DB, namespace, table string) error {
	name := pgx.Identifier{namespace, table}.Sanitize()
	// Explicit IDs do not advance PostgreSQL sequences.
	return tx.Exec("SELECT setval(pg_get_serial_sequence(?, 'id'), "+
		"COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM "+name, name).Error
}
