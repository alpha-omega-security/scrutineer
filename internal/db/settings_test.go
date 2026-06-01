package db

import "testing"

func TestSetting_setGetUpsert(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := GetSetting(gdb, SettingConcurrency); ok {
		t.Fatal("expected missing key to report not found")
	}
	if got := SettingInt(gdb, SettingConcurrency); got != 0 {
		t.Errorf("SettingInt(missing) = %d, want 0", got)
	}

	if err := SetSetting(gdb, SettingConcurrency, "8"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if v, ok := GetSetting(gdb, SettingConcurrency); !ok || v != "8" {
		t.Errorf("GetSetting = (%q, %v), want (\"8\", true)", v, ok)
	}
	if got := SettingInt(gdb, SettingConcurrency); got != 8 {
		t.Errorf("SettingInt = %d, want 8", got)
	}

	// Re-setting the same key updates in place rather than erroring on the
	// duplicate primary key.
	if err := SetSetting(gdb, SettingConcurrency, "16"); err != nil {
		t.Fatalf("SetSetting upsert: %v", err)
	}
	if got := SettingInt(gdb, SettingConcurrency); got != 16 {
		t.Errorf("SettingInt after upsert = %d, want 16", got)
	}
}

func TestSettingInt_unparseable(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(gdb, SettingDefaultMaxTurns, "not-a-number"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if got := SettingInt(gdb, SettingDefaultMaxTurns); got != 0 {
		t.Errorf("SettingInt(unparseable) = %d, want 0", got)
	}
}
