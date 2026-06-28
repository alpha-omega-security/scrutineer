package skills

import "os"

func testGitEnv() []string {
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
