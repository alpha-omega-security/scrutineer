package db

import (
	"reflect"
	"strings"
	"unicode/utf8"

	"gorm.io/gorm"
)

// SanitizePGText makes s safe for a PostgreSQL text column. PostgreSQL rejects
// NUL bytes (0x00) and invalid UTF-8; SQLite accepts both. Scan, finding, and
// chat text is captured verbatim from container/tool/model output and from
// repository file bytes, any of which can carry those, so it must be scrubbed
// before it reaches a text column. Empty and already-clean strings return
// unchanged after two linear scans, so the common case is cheap.
func SanitizePGText(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

// registerTextSanitizer installs a Create/Update callback that scrubs string
// values on their way to the database. Without it, a stray NUL byte or invalid
// UTF-8 sequence in captured output makes the write fail on PostgreSQL — for a
// scan that is the terminal status write, so the row is stranded in 'running'
// (its re-delivered job is then dropped as stale). One callback covers every
// write form: struct Create/Save/Updates (via the statement's reflect value)
// and column/map updates like Update("log", ...) (via the map destination).
//
// It is registered only for PostgreSQL. SQLite tolerates these bytes, so the
// default backend keeps its historical behaviour and pays no reflect cost.
func registerTextSanitizer(gdb *gorm.DB) error {
	if err := gdb.Callback().Create().Before("gorm:create").Register("scrutineer:sanitize_text", sanitizeStatementText); err != nil {
		return err
	}
	return gdb.Callback().Update().Before("gorm:update").Register("scrutineer:sanitize_text", sanitizeStatementText)
}

// sanitizeStatementText scrubs the pending write in place. Map destinations
// (column/map updates) have their string values rewritten; everything else is
// a struct or slice of structs reachable through the statement's reflect value.
func sanitizeStatementText(db *gorm.DB) {
	if db.Statement == nil {
		return
	}
	switch dest := db.Statement.Dest.(type) {
	case map[string]interface{}:
		for k, v := range dest {
			switch t := v.(type) {
			case string:
				dest[k] = SanitizePGText(t)
			case *string:
				if t != nil {
					*t = SanitizePGText(*t)
				}
			}
		}
	default:
		sanitizeReflectStrings(db.Statement.ReflectValue)
	}
}

// sanitizeReflectStrings rewrites the settable top-level string and *string
// fields of a struct value, or of each element of a slice/array of structs
// (batch insert). Nested structs are not descended into: the models keep their
// free text at the top level, and skipping them avoids touching stdlib structs
// such as time.Time whose fields are unexported.
func sanitizeReflectStrings(rv reflect.Value) {
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !rv.IsNil() {
			sanitizeReflectStrings(rv.Elem())
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			sanitizeReflectStrings(rv.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			f := rv.Field(i)
			if !f.CanSet() {
				continue
			}
			switch f.Kind() {
			case reflect.String:
				f.SetString(SanitizePGText(f.String()))
			case reflect.Pointer:
				if !f.IsNil() && f.Elem().Kind() == reflect.String {
					f.Elem().SetString(SanitizePGText(f.Elem().String()))
				}
			}
		}
	}
}
