package web

import "testing"

func TestValidEffort(t *testing.T) {
	for _, e := range []string{"low", "medium", "high", "xhigh", "max"} {
		if !ValidEffort(e) {
			t.Errorf("ValidEffort(%q) = false, want true", e)
		}
	}
	for _, e := range []string{"", "High", "extreme", "garbage"} {
		if ValidEffort(e) {
			t.Errorf("ValidEffort(%q) = true, want false", e)
		}
	}
}

func TestDefaultEffort(t *testing.T) {
	defer restoreEffort(defaultEffortOverride)

	defaultEffortOverride = ""
	if got := DefaultEffort(); got != builtinDefaultEffort {
		t.Errorf("DefaultEffort() with no override = %q, want %q", got, builtinDefaultEffort)
	}
	defaultEffortOverride = "max"
	if got := DefaultEffort(); got != "max" {
		t.Errorf("DefaultEffort() with override = %q, want max", got)
	}
}

func TestSetDefaultEffort(t *testing.T) {
	defer restoreEffort(defaultEffortOverride)

	defaultEffortOverride = "high"
	SetDefaultEffort("xhigh")
	if defaultEffortOverride != "xhigh" {
		t.Errorf("SetDefaultEffort(xhigh) = %q, want xhigh", defaultEffortOverride)
	}
	// An empty or unknown value must not clobber the current setting.
	SetDefaultEffort("")
	SetDefaultEffort("garbage")
	if defaultEffortOverride != "xhigh" {
		t.Errorf("invalid SetDefaultEffort changed it to %q, want xhigh", defaultEffortOverride)
	}
}

func restoreEffort(v string) { defaultEffortOverride = v }
