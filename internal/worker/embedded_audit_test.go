package worker

import (
	"testing"

	"scrutineer/internal/db"
)

const embeddedAuditFinding = `{"id":"F1","title":"Firmware image installed on an unauthenticated manifest digest","severity":"High","confidence":"high","cwe":"CWE-494","location":"firmware/ota.py:15","reachability":"reachable","quality_tier":"high","trace":"apply_update receives the image and manifest from the update server and checks only the SHA-256 digest stored in that manifest before writing the inactive slot and marking it bootable.","boundary":"A malicious update server or on-path attacker installs arbitrary firmware on the device.","validation":"Static trace finds no signature or trusted-key check between download and flash_write.","discovered_via":"source","rating":"High: remote code execution on the device by whoever controls the update channel.","references":[{"url":"https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V3-Software_Platform_Requirements.md","summary":"ISVS 1.0RC software update guidance","tags":"isvs"}]}`

func embeddedAuditReport(findings string) string {
	return `{"review_status":"reviewed","findings":[` + findings + `],"notes":"Static source review only.","scope":"Sensor firmware.","source_sink_inventory":["firmware/ota.py:15 writes a downloaded image to the inactive slot."],"negative_results":["firmware/ota.py:26 verifies the configuration signature and rejects non-increasing versions."],"unverified_assumptions":["Secure boot fuse settings were not available in the checkout."],"design_properties":["firmware/ota.py:8 keeps a single inactive slot for updates."]}`
}

func TestEmbeddedAuditSchemaAndIngestion(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/audit-embedded/schema.json")
	report := embeddedAuditReport(embeddedAuditFinding)
	if detail := ValidateReportSchema(schema, report); detail != "" {
		t.Fatal(detail)
	}
	repo, gdb := runSkillWithReport(t, "findings", report)
	var findings []db.Finding
	if err := gdb.Where("repository_id = ?", repo.ID).Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].CWE != "CWE-494" {
		t.Fatalf("findings=%+v", findings)
	}
	var refs []db.FindingReference
	if err := gdb.Where("finding_id = ?", findings[0].ID).Find(&refs).Error; err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Summary != "ISVS 1.0RC software update guidance" {
		t.Fatalf("references=%+v", refs)
	}
}

func TestEmbeddedAuditSchemaRejectsInvalidReports(t *testing.T) {
	checkModeSchemaRejectsInvalid(t, modeSchemaCase{
		schemaPath: "../../skills/audit-embedded/schema.json", report: embeddedAuditReport, finding: embeddedAuditFinding,
		reference:    `{"url":"https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V3-Software_Platform_Requirements.md","summary":"ISVS 1.0RC software update guidance","tags":"isvs"}`,
		nonMatchNote: "provision.py only runs on the host.",
	})
}
