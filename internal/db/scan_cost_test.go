package db

import "testing"

func TestScanCostUnpriced(t *testing.T) {
	tests := []struct {
		name string
		scan Scan
		want bool
	}{
		{"no usage", Scan{}, false},
		{"priced", Scan{CostUSD: 0.5, InputTokens: 10}, false},
		{"input tokens without cost", Scan{InputTokens: 10}, true},
		{"output tokens without cost", Scan{OutputTokens: 1}, true},
		{"cache reads without cost", Scan{CacheReadTokens: 1}, true},
		{"cache writes without cost", Scan{CacheWriteTokens: 1}, true},
	}
	for _, tt := range tests {
		if got := tt.scan.CostUnpriced(); got != tt.want {
			t.Errorf("%s: CostUnpriced = %v, want %v", tt.name, got, tt.want)
		}
	}
}
