package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
)

func TestMigratorProcess(_ *testing.T) {
	if os.Getenv("SCRUTINEER_MIGRATOR_PROCESS") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("migrate-sqlite-to-postgres", flag.ExitOnError)
	os.Args = append([]string{os.Args[0]}, strings.Split(os.Getenv("SCRUTINEER_MIGRATOR_ARGS"), "\n")...)
	main()
	os.Exit(0)
}

func migrateCLI(t *testing.T, path, dsn string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigratorProcess$")
	cmd.Env = append(os.Environ(), "SCRUTINEER_MIGRATOR_PROCESS=1",
		"SCRUTINEER_MIGRATOR_ARGS=-sqlite\n"+path+"\n-postgres\n"+dsn)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func sqliteSource(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.db")
	source, err := db.Open(path)
	must(t, err)
	t.Cleanup(func() { closeDB(source) })
	return source, path
}

func postgresDestination(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	destination, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: dsn})
	must(t, err)
	t.Cleanup(func() { closeDB(destination) })
	return destination
}

func TestMigrationTableCoverage(t *testing.T) {
	src, _ := sqliteSource(t)
	tables, err := migrationTables(src)
	must(t, err)
	must(t, checkSource(src, tables))
	var actual []string
	must(t, src.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&actual).Error)
	if len(actual) != len(tables) {
		t.Fatalf("database has %d application tables; migrator has %d", len(actual), len(tables))
	}
}

func TestPostgresMigration(t *testing.T) {
	dsn := ownerDSN(t)
	src, path := sqliteSource(t)
	seedHistory(t, src)
	must(t, src.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error)
	before, err := os.ReadFile(path)
	must(t, err)
	output, err := migrateCLI(t, path, dsn)
	if err != nil {
		t.Fatalf("CLI: %v\n%s", err, output)
	}
	after, err := os.ReadFile(path)
	must(t, err)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("migration changed the source database")
	}
	dst := postgresDestination(t, dsn)
	var tables []string
	must(t, src.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&tables).Error)
	for _, table := range tables {
		var want, got int64
		must(t, src.Table(table).Count(&want).Error)
		must(t, dst.Table(table).Count(&got).Error)
		if table == "settings" {
			got-- // PostgreSQL owns its schema-version setting.
		}
		if want == 0 || got != want {
			t.Errorf("%s: got %d rows, want %d nonzero rows", table, got, want)
		}
	}
	var scan db.Scan
	must(t, dst.First(&scan, 1).Error)
	if scan.Commit != "abc123" || scan.FindingID == nil || *scan.FindingID != 1 ||
		scan.Report != "hasnul" || scan.Log != db.SanitizePGText("bad\xfftext") {
		t.Fatalf("scan data changed: commit=%q finding=%v report=%q log=%q", scan.Commit, scan.FindingID, scan.Report, scan.Log)
	}
	var nulls bool
	must(t, dst.Raw("SELECT created_at IS NULL AND fetched_at IS NULL FROM repositories WHERE id = 1").Scan(&nulls).Error)
	if !nulls {
		t.Error("NULL timestamps were replaced")
	}
	var skill db.Skill
	must(t, dst.First(&skill, 1).Error)
	if skill.Active || skill.Version != 0 {
		t.Errorf("stored zero values replaced by defaults: active=%t version=%d", skill.Active, skill.Version)
	}
	var upload db.SBOMUpload
	must(t, dst.First(&upload, 1).Error)
	if !bytes.Equal(upload.Raw, []byte{0, 0xff, 1}) || upload.Origin != "" {
		t.Errorf("SBOM bytes or empty origin changed: raw=%v origin=%q", upload.Raw, upload.Origin)
	}
	var message db.ChatMessage
	must(t, dst.First(&message, 1).Error)
	wantTime := time.Date(2020, 2, 3, 4, 5, 6, 123456000, time.UTC)
	if message.Content != "retain this conversation" || !message.CreatedAt.Equal(wantTime) {
		t.Errorf("chat content/timestamp changed: %+v", message)
	}
	var badConstraints int64
	must(t, dst.Raw("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND connamespace = current_schema()::regnamespace AND (condeferrable OR NOT convalidated)").Scan(&badConstraints).Error)
	if badConstraints != 0 {
		t.Errorf("%d constraints were not restored and validated", badConstraints)
	}
	for _, model := range []any{
		&db.Repository{URL: "https://example.com/after"},
		&db.Scan{RepositoryID: 1, Status: db.ScanDone},
		&db.Finding{ScanID: 1, Title: "after migration"},
	} {
		must(t, dst.Create(model).Error)
	}
	if output, err := migrateCLI(t, path, dsn); err == nil || !strings.Contains(output, "not empty") {
		t.Fatalf("rerun should refuse a populated destination: %v\n%s", err, output)
	}
}

func ownerDSN(t *testing.T) string {
	t.Helper()
	dsn := testutil.PostgresDSN(t)
	admin, err := sql.Open("pgx", dsn)
	must(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	role := "migrator_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{role}.Sanitize()
	_, err = admin.Exec("CREATE ROLE " + identifier + " NOSUPERUSER NOCREATEDB NOCREATEROLE")
	must(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec("DROP OWNED BY " + identifier + " CASCADE")
		must(t, err)
		_, err = admin.Exec("DROP ROLE " + identifier)
		must(t, err)
	})
	_, err = admin.Exec("GRANT CREATE ON SCHEMA public TO " + identifier)
	must(t, err)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		must(t, err)
		query := parsed.Query()
		query.Set("options", "-c role="+role)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return dsn + " options='-c role=" + role + "'"
}

func seedHistory(t *testing.T, src *gorm.DB) {
	t.Helper()
	const count = batchSize*2 + 1
	var repositories []db.Repository
	var scans []db.Scan
	var findings []db.Finding
	var labels []db.FindingLabel
	var maintainers []db.Maintainer
	var repoLinks []repositoryMaintainer
	var findingLinks []findingLabel
	for i := uint(1); i <= count; i++ {
		repositories = append(repositories, db.Repository{ID: i, URL: fmt.Sprintf("https://example.com/repo-%d", i)})
		scans = append(scans, db.Scan{ID: i, RepositoryID: i, Status: db.ScanDone, Commit: "abc123"})
		findings = append(findings, db.Finding{ID: i, ScanID: i, Title: fmt.Sprintf("finding-%d", i)})
		labels = append(labels, db.FindingLabel{ID: i, Name: fmt.Sprintf("label-%d", i)})
		maintainers = append(maintainers, db.Maintainer{ID: i, Login: fmt.Sprintf("maintainer-%d", i)})
		repoLinks = append(repoLinks, repositoryMaintainer{RepositoryID: i, MaintainerID: i})
		findingLinks = append(findingLinks, findingLabel{FindingID: i, FindingLabelID: i})
	}
	for _, rows := range []any{&repositories, &scans, &findings, &labels, &maintainers, &repoLinks, &findingLinks} {
		must(t, src.CreateInBatches(rows, batchSize).Error)
	}
	must(t, src.Model(&db.Scan{}).Where("id = 1").Updates(map[string]any{
		"finding_id": 1, "report": "has\x00nul", "log": "bad\xfftext",
	}).Error)
	for _, row := range []any{
		&db.ExpectedFinding{RepositoryID: 1, File: "app.rb", CWE: "CWE-89"},
		&db.FindingNote{FindingID: 1, Body: "analyst note"},
		&db.FindingCommunication{FindingID: 1, Body: "disclosure"},
		&db.FindingReference{FindingID: 1, URL: "https://example.com/reference"},
		&db.FindingHistory{FindingID: 1, Field: "status", NewValue: "confirmed"},
		&db.FindingReview{FindingID: 1, Verdict: "true_positive"},
		&db.FindingVerification{FindingID: 1, ScanID: 1, Status: "verified", Report: "{}"},
		&db.FindingAttackPath{FindingID: 1, ScanID: 1, ProductionViability: "VIABLE", Report: "{}"},
		&db.RemediationAttempt{FindingID: 1, PatchScanID: 1, Attempt: 1, Patch: "diff", BaseCommit: "abc123"},
		&db.RemediationValidation{FindingID: 1, RemediationAttemptID: 1, ScanID: 1, RootCauseStatus: "failed_to_bypass", Report: "{}"},
		&db.AuditEvent{Kind: "finding.status", SubjectType: "finding", SubjectID: 1, Payload: "{}"},
		&db.Dependency{RepositoryID: 1, Name: "dependency"},
		&db.Package{RepositoryID: 1, Name: "package"},
		&db.PackageAlternative{RepositoryID: 1, PURL: "pkg:gem/successor", Kind: "successor"},
		&db.Dependent{RepositoryID: 1, Name: "dependent"},
		&db.FindingDependent{FindingID: 1, DependentID: 1, Status: "known_affected"},
		&db.Advisory{RepositoryID: 1, UUID: "advisory"},
		&db.AdvisoryAudit{RepositoryID: 1, ScanID: 1, AdvisoryUUID: "advisory", Status: "fixed"},
		&db.Skill{Name: "audit", Body: "recipe"},
		&db.Subproject{RepositoryID: 1, Path: "lib"},
		&db.ComplianceControl{RepositoryID: 1, ScanID: 1, ControlID: "control", Status: "PASS"},
		&db.SBOMUpload{Name: "snapshot", Raw: []byte{0, 0xff, 1}},
		&db.SBOMPackage{SBOMUploadID: 1, Name: "package"},
		&db.CNA{ShortName: "authority"},
		&db.Setting{Key: "concurrency", Value: "4"},
		&db.Conversation{RepositoryID: 1, Title: "triage"},
		&db.ChatMessage{ConversationID: 1, Role: "user", Content: "retain this conversation",
			CreatedAt: time.Date(2020, 2, 3, 4, 5, 6, 123456000, time.UTC)},
		&db.InterchangeRecord{Feed: "peer", PredicateType: "claim", SubjectDigest: "digest", Record: "{}"},
	} {
		must(t, src.Create(row).Error)
	}
	must(t, src.Exec("UPDATE repositories SET created_at = NULL, fetched_at = NULL WHERE id = 1").Error)
	must(t, src.Exec("UPDATE skills SET active = false, version = 0 WHERE id = 1").Error)
	must(t, src.Exec("UPDATE sbom_uploads SET origin = '' WHERE id = 1").Error)
}

func TestPostgresMigrationRejectsUnsafeSources(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		want string
	}{
		{"queued", "INSERT INTO scans (repository_id, kind, status) VALUES (1, 'skill', 'queued')", "queued/running"},
		{"running", "INSERT INTO scans (repository_id, kind, status) VALUES (1, 'skill', 'Running')", "queued/running"},
		{"queue", "CREATE TABLE goqite (id TEXT); INSERT INTO goqite VALUES ('pending')", "job queue"},
		{"unknown table", "CREATE TABLE extra_history (id INTEGER)", "source table extra_history"},
		{"unknown column", "ALTER TABLE repositories ADD COLUMN extra_history TEXT", "source column repositories.extra_history"},
		{"older schema", "ALTER TABLE findings DROP COLUMN title", "source is missing column findings.title"},
		{"missing table", "DROP TABLE audit_events", "source is missing table audit_events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := testutil.PostgresDSN(t)
			src, path := sqliteSource(t)
			must(t, src.Create(&db.Repository{URL: "https://example.com/repo"}).Error)
			must(t, src.Exec(tc.sql).Error)
			output, err := migrateCLI(t, path, dsn)
			if err == nil || !strings.Contains(output, tc.want) {
				t.Fatalf("expected %q: %v\n%s", tc.want, err, output)
			}
		})
	}
}

func TestPostgresMigrationRejectsDestinationData(t *testing.T) {
	for _, model := range []any{&db.Setting{Key: "concurrency", Value: "8"}, &db.FindingLabel{Name: "existing"}} {
		t.Run(fmt.Sprintf("%T", model), func(t *testing.T) {
			dsn := testutil.PostgresDSN(t)
			dst := postgresDestination(t, dsn)
			must(t, dst.Create(model).Error)
			src, path := sqliteSource(t)
			must(t, src.Create(&db.Repository{URL: "https://example.com/repo"}).Error)
			output, err := migrateCLI(t, path, dsn)
			if err == nil || !strings.Contains(output, "not empty") {
				t.Fatalf("expected refusal: %v\n%s", err, output)
			}
			var count int64
			must(t, dst.Model(&db.Repository{}).Count(&count).Error)
			if count != 0 {
				t.Fatalf("copied %d repositories into populated destination", count)
			}
		})
	}
}

func TestPostgresMigrationRollsBackInvalidRelationships(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	src, path := sqliteSource(t)
	must(t, src.Create(&db.Repository{URL: "https://example.com/repo"}).Error)
	must(t, src.Exec("PRAGMA foreign_keys = OFF").Error)
	must(t, src.Exec("INSERT INTO scans (repository_id, kind, status) VALUES (999, 'skill', 'done')").Error)
	output, err := migrateCLI(t, path, dsn)
	if err == nil || !strings.Contains(output, "validate migrated relationships") {
		t.Fatalf("expected FK validation error: %v\n%s", err, output)
	}
	dst := postgresDestination(t, dsn)
	var count int64
	must(t, dst.Model(&db.Repository{}).Count(&count).Error)
	if count != 0 {
		t.Fatalf("failed migration left %d repositories", count)
	}
	must(t, src.Exec("UPDATE scans SET repository_id = 1").Error)
	if output, err := migrateCLI(t, path, dsn); err != nil {
		t.Fatalf("retry after fixing source: %v\n%s", err, output)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
