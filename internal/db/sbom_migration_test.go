package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpen_rejectsNewerDatabaseSchemaBeforeMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	gdb, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := gdb.Raw("PRAGMA user_version").Scan(&version).Error; err != nil {
		t.Fatal(err)
	}
	if version != databaseSchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, databaseSchemaVersion)
	}
	if err := gdb.Exec("ALTER TABLE sbom_packages ADD COLUMN repository_id integer").Error; err != nil {
		t.Fatal(err)
	}
	newerVersion := databaseSchemaVersion + 1
	if err := gdb.Exec(fmt.Sprintf("PRAGMA user_version = %d", newerVersion)).Error; err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	wantError := fmt.Sprintf("database schema version %d is newer", newerVersion)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("Open error = %v, want newer schema rejection", err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := raw.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	}()
	var oldColumnCount int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sbom_packages') WHERE name = 'repository_id'`).Scan(&oldColumnCount); err != nil {
		t.Fatal(err)
	}
	if oldColumnCount != 1 {
		t.Fatal("schema changed before version rejection")
	}
}

func TestPreMigrate_mergesDuplicateSBOMRepositoryColumns(t *testing.T) {
	cases := []struct {
		name string
		ddl  string
	}{
		{
			name: "legacy database upgraded then downgraded",
			ddl:  "CREATE TABLE \"sbom_packages\" (`id` integer PRIMARY KEY AUTOINCREMENT,`sbom_upload_id` integer NOT NULL,`name` text,`version` text,`p_url` text,`ecosystem` text,`license` text,`scope` text,\"source_repository_id\" integer,`resolve_error` text,`created_at` datetime, `repository_id` integer,CONSTRAINT `fk_sbom_packages_repository` FOREIGN KEY (\"source_repository_id\") REFERENCES `repositories`(`id`),CONSTRAINT `fk_sbom_uploads_packages` FOREIGN KEY (`sbom_upload_id`) REFERENCES `sbom_uploads`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_sbom_packages_source_repository` FOREIGN KEY (`source_repository_id`) REFERENCES `repositories`(`id`))",
		},
		{
			name: "fresh current database downgraded",
			ddl:  "CREATE TABLE \"sbom_packages\" (`id` integer PRIMARY KEY AUTOINCREMENT,`sbom_upload_id` integer NOT NULL,`name` text,`version` text,`p_url` text,`ecosystem` text,`license` text,`scope` text,`source_repository_id` integer,`resolve_error` text,`created_at` datetime,`repository_id` integer,CONSTRAINT `fk_sbom_packages_source_repository` FOREIGN KEY (`source_repository_id`) REFERENCES `repositories`(`id`),CONSTRAINT `fk_sbom_uploads_packages` FOREIGN KEY (`sbom_upload_id`) REFERENCES `sbom_uploads`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_sbom_packages_repository` FOREIGN KEY (`repository_id`) REFERENCES `repositories`(`id`))",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testSBOMRepositoryColumnMerge(t, tc.ddl)
		})
	}
}

func testSBOMRepositoryColumnMerge(t *testing.T, ddl string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "both.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE repositories (id INTEGER PRIMARY KEY, url TEXT NOT NULL, name TEXT NOT NULL)`,
		`INSERT INTO repositories (id, url, name) VALUES (101, 'https://example.com/one', 'one'), (102, 'https://example.com/two', 'two')`,
		`CREATE TABLE "sbom_uploads" (` +
			"`id` integer PRIMARY KEY AUTOINCREMENT,`name` text,`filename` text,`format` text,`spec_version` text," +
			"`raw` blob,`package_count` integer,`import_pending` numeric NOT NULL DEFAULT false,`created_at` datetime," +
			"`updated_at` datetime,`origin` text NOT NULL DEFAULT \"uploaded\",`repository_id` integer,`scan_id` integer," +
			"`commit` text,`current` numeric,CONSTRAINT `fk_sbom_uploads_repository` FOREIGN KEY (`repository_id`) REFERENCES `repositories`(`id`))",
		`INSERT INTO sbom_uploads (id, name) VALUES (1, 'old')`,
		`CREATE INDEX idx_sbom_uploads_origin ON sbom_uploads(origin)`,
		`CREATE INDEX idx_sbom_uploads_repo_current ON sbom_uploads(repository_id, current)`,
		`CREATE INDEX idx_sbom_uploads_scan_id ON sbom_uploads(scan_id)`,
		ddl,
		`CREATE INDEX idx_sbom_packages_repository_id ON sbom_packages(repository_id)`,
		`CREATE INDEX idx_sbom_packages_source_repository_id ON sbom_packages(source_repository_id)`,
		`INSERT INTO sbom_packages (id, sbom_upload_id, name, source_repository_id, repository_id) VALUES
			(1, 1, 'conflict', 101, 102),
			(2, 1, 'late-only', NULL, 102),
			(3, 1, 'old-only', 101, NULL)`,
	}
	for _, stmt := range stmts {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	gdb, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if gdb.Migrator().HasColumn(&SBOMPackage{}, "repository_id") {
		t.Fatal("repository_id still exists")
	}
	if gdb.Migrator().HasConstraint(&SBOMPackage{}, "fk_sbom_packages_repository") {
		t.Fatal("legacy repository constraint still exists")
	}
	if !gdb.Migrator().HasConstraint(&SBOMPackage{}, "fk_sbom_packages_source_repository") {
		t.Fatal("source repository constraint does not exist")
	}
	if gdb.Migrator().HasIndex(&SBOMPackage{}, "idx_sbom_packages_repository_id") {
		t.Fatal("legacy repository index still exists")
	}
	var packages []SBOMPackage
	if err := gdb.Order("id").Find(&packages).Error; err != nil {
		t.Fatal(err)
	}
	want := []uint{102, 102, 101}
	if len(packages) != len(want) {
		t.Fatalf("package count = %d, want %d", len(packages), len(want))
	}
	for i, pkg := range packages {
		if pkg.SourceRepositoryID == nil || *pkg.SourceRepositoryID != want[i] {
			t.Errorf("package %d source_repository_id = %v, want %d", pkg.ID, pkg.SourceRepositoryID, want[i])
		}
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("second Open: %v", err)
	}
}
