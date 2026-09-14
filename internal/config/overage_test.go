package config

import "testing"

func TestPauseOnOverageConfig(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		value := "false"
		if enabled {
			value = "true"
		}
		cfg, err := Load(write(t, "pause_on_overage: "+value+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PauseOnOverage == nil || *cfg.PauseOnOverage != enabled {
			t.Fatalf("pause_on_overage=%v", cfg.PauseOnOverage)
		}
	}
	cfg, err := Load(write(t, "{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PauseOnOverage != nil {
		t.Fatal("omitted option should retain default")
	}
	if _, err := Load(write(t, "pause_on_overage: invalid\n")); err == nil {
		t.Fatal("invalid boolean accepted")
	}
}
