package main

import (
	"scrutineer/internal/config"
	"testing"
)

func TestPauseOnOverageFlagPrecedence(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := &flags{set: map[string]bool{}}
		f.merge(&config.Config{PauseOnOverage: new(enabled)})
		if f.pauseOnOverage != enabled {
			t.Fatal("config not applied")
		}
		f = &flags{pauseOnOverage: !enabled, set: map[string]bool{"pause-on-overage": true}}
		f.merge(&config.Config{PauseOnOverage: new(enabled)})
		if f.pauseOnOverage != !enabled {
			t.Fatal("explicit CLI option overwritten")
		}
	}
}
