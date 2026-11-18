package web

import (
	"os"
	"testing"

	"scrutineer/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.IsolateGitConfig()
	os.Exit(m.Run())
}
