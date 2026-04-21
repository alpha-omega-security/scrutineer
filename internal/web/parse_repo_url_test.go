package web

import "testing"

func TestParseRepoInput(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     RepoInput
		wantErr  bool
	}{
		{
			name:  "plain github url without .git",
			input: "https://github.com/rails/rails",
			want:  RepoInput{CloneURL: "https://github.com/rails/rails.git"},
		},
		{
			name:  "plain github url with .git",
			input: "https://github.com/rails/rails.git",
			want:  RepoInput{CloneURL: "https://github.com/rails/rails.git"},
		},
		{
			name:  "github tree url with sub-path",
			input: "https://github.com/apache/airflow/tree/main/airflow-core",
			want: RepoInput{
				CloneURL: "https://github.com/apache/airflow.git",
				SubPath:  "airflow-core",
				Branch:   "main",
			},
		},
		{
			name:  "github tree url with nested sub-path",
			input: "https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api",
			want: RepoInput{
				CloneURL: "https://github.com/kubernetes/kubernetes.git",
				SubPath:  "staging/src/k8s.io/api",
				Branch:   "master",
			},
		},
		{
			name:  "github tree url with release branch",
			input: "https://github.com/apache/airflow/tree/v2.9.0/airflow-core",
			want: RepoInput{
				CloneURL: "https://github.com/apache/airflow.git",
				SubPath:  "airflow-core",
				Branch:   "v2.9.0",
			},
		},
		{
			name:  "github tree url pointing at root of branch",
			input: "https://github.com/apache/airflow/tree/main",
			want: RepoInput{
				CloneURL: "https://github.com/apache/airflow.git",
				SubPath:  "",
				Branch:   "main",
			},
		},
		{
			name:  "fragment form explicit sub-path",
			input: "https://gitlab.com/group/project#services/api",
			want: RepoInput{
				CloneURL: "https://gitlab.com/group/project.git",
				SubPath:  "services/api",
			},
		},
		{
			name:  "fragment form with leading slash",
			input: "https://github.com/rails/rails#/railties",
			want: RepoInput{
				CloneURL: "https://github.com/rails/rails.git",
				SubPath:  "railties",
			},
		},
		{
			name:    "non-https rejected",
			input:   "git@github.com:foo/bar.git",
			wantErr: true,
		},
		{
			name:    "file scheme rejected",
			input:   "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "empty rejected",
			input:   "   ",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRepoInput(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
