// Package testutil holds helpers shared by the internal/* test suites.
// It is imported only from _test.go files.
package testutil

import "os"

// GitEnv returns an environment for exec'd git commands in tests: it
// suppresses the host's global/system git config and pins author/committer
// identity so commits are reproducible regardless of the developer's or CI
// runner's local git setup.
func GitEnv() []string {
	env := append([]string{}, os.Environ()...)
	return append(env,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Scrutineer Tests",
		"GIT_AUTHOR_EMAIL=scrutineer-tests@example.invalid",
		"GIT_COMMITTER_NAME=Scrutineer Tests",
		"GIT_COMMITTER_EMAIL=scrutineer-tests@example.invalid",
	)
}
