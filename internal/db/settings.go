package db

import (
	"strconv"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Setting is a persisted operator-tunable key/value. It backs the runtime
// knobs the Settings page exposes (concurrency, default turn cap) so a
// change survives a restart instead of living only in process memory.
type Setting struct {
	Key   string `gorm:"primarykey"`
	Value string
}

// Setting keys.
const (
	SettingConcurrency     = "concurrency"
	SettingDefaultMaxTurns = "default_max_turns"
	SettingModelTierMid    = "model_tier_mid"
	SettingModelTierHigh   = "model_tier_high"
	SettingModelTierMax    = "model_tier_max"
)

// GetSetting returns the stored value for key and whether a row exists. It
// uses Find rather than First so a missing key is a clean (zero rows) result
// instead of a logged ErrRecordNotFound: absent keys are the common case
// (read on every scan and settings page load).
func GetSetting(gdb *gorm.DB, key string) (string, bool) {
	var s Setting
	res := gdb.Where("key = ?", key).Limit(1).Find(&s)
	if res.Error != nil || res.RowsAffected == 0 {
		return "", false
	}
	return s.Value, true
}

// SetSetting upserts key to value. SQLite has no UPDATE-or-INSERT in GORM's
// Save for a string primary key, so it goes through an ON CONFLICT clause.
func SetSetting(gdb *gorm.DB, key, value string) error {
	return gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&Setting{Key: key, Value: value}).Error
}

// SettingInt returns the stored value parsed as an int, or 0 when the key is
// absent or unparseable. Callers treat 0 as "not configured".
func SettingInt(gdb *gorm.DB, key string) int {
	v, ok := GetSetting(gdb, key)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}
