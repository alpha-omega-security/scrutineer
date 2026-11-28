package worker

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMavenSettings(t *testing.T) {
	const full = `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <proxies>
    <proxy>
      <id>scrutineer-egress</id>
      <active>true</active>
      <protocol>https</protocol>
      <host>10.89.1.2</host>
      <port>3128</port>
      <username>scrutineer</username>
      <password>tok</password>
    </proxy>
  </proxies>
  <mirrors>
    <mirror>
      <id>scrutineer-package-repository</id>
      <mirrorOf>central</mirrorOf>
      <url>https://pkgs.example.com/maven/</url>
    </mirror>
  </mirrors>
</settings>
`
	tests := []struct {
		name     string
		mirror   string
		proxy    string
		want     string
		contains []string
		absent   []string
	}{
		{
			name:     "mirror only",
			mirror:   "https://pkgs.example.com/maven/",
			contains: []string{"<mirrorOf>central</mirrorOf>", "<url>https://pkgs.example.com/maven/</url>"},
			absent:   []string{"<proxies>"},
		},
		{
			name:     "proxy only",
			proxy:    "http://scrutineer:tok@10.89.1.2:3128",
			contains: []string{"<protocol>https</protocol>", "<host>10.89.1.2</host>", "<port>3128</port>"},
			absent:   []string{"<mirrors>"},
		},
		{
			name:   "both",
			mirror: "https://pkgs.example.com/maven/",
			proxy:  "http://scrutineer:tok@10.89.1.2:3128",
			want:   full,
		},
		{
			name:     "proxy without userinfo",
			proxy:    "http://10.89.1.2:3128",
			contains: []string{"<host>10.89.1.2</host>"},
			absent:   []string{"<username>", "<password>"},
		},
		{
			name:     "escapes mirror url",
			mirror:   "https://maven.example.org/repo?a=1&b=2",
			contains: []string{"<url>https://maven.example.org/repo?a=1&amp;b=2</url>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mavenSettings(tt.mirror, tt.proxy)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && string(got) != tt.want {
				t.Errorf("settings = %q, want %q", got, tt.want)
			}
			for _, c := range tt.contains {
				if !strings.Contains(string(got), c) {
					t.Errorf("settings missing %q: %s", c, got)
				}
			}
			for _, a := range tt.absent {
				if strings.Contains(string(got), a) {
					t.Errorf("settings unexpectedly contain %q: %s", a, got)
				}
			}
		})
	}

	t.Run("proxy without port", func(t *testing.T) {
		_, err := mavenSettings("", "http://scrutineer:secrettoken@10.89.1.2")
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "secrettoken") {
			t.Errorf("error leaks the token: %v", err)
		}
	})
}

func readMavenSettings(t *testing.T, d ContainerRunner) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.mavenSettingsDir, filepath.FromSlash(mavenSettingsPath)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrepareScanConfig_HardenedSidecarProxy(t *testing.T) {
	const repo = "https://pkgs.example.com/maven/"
	hnet := hardenedNet{proxyEndpoint: "10.89.1.2:3128"}
	d := ContainerRunner{
		Hardened:        true,
		MavenRepository: repo,
		Egress:          EgressSidecarConfig{Token: "tok"},
		ScanConfigRoot:  t.TempDir(),
	}
	d, cleanup, err := d.prepareScanConfig(hnet)
	if err != nil {
		t.Fatal(err)
	}
	dir := d.mavenSettingsDir
	got := readMavenSettings(t, d)
	for _, want := range []string{"<host>10.89.1.2</host>", "<port>3128</port>", "<password>tok</password>", "<url>" + repo + "</url>"} {
		if !strings.Contains(got, want) {
			t.Errorf("settings missing %q: %s", want, got)
		}
	}

	args := d.buildContainerBaseArgs("/work/abs", hnet, "/work")
	if !hasArgPair(args, "-v", dir+":"+ScanConfigMountDir+":ro") {
		t.Errorf("scan config mount missing: %v", args)
	}
	if !hasArgPair(args, "-e", "MAVEN_ARGS=--global-settings /scan-config/maven/settings.xml") {
		t.Errorf("MAVEN_ARGS missing: %v", args)
	}
	var proxy *url.URL
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "HTTPS_PROXY="); ok {
			if proxy, err = url.Parse(v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if proxy == nil {
		t.Fatalf("HTTPS_PROXY missing: %v", args)
	}
	if want := "<host>" + proxy.Hostname() + "</host>"; !strings.Contains(got, want) {
		t.Errorf("settings missing %q: %s", want, got)
	}
	if want := "<port>" + proxy.Port() + "</port>"; !strings.Contains(got, want) {
		t.Errorf("settings missing %q: %s", want, got)
	}

	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("scan config dir still exists after cleanup: %v", err)
	}
}

func TestPrepareScanConfig_HostProxyNotHardened(t *testing.T) {
	d := ContainerRunner{
		MavenRepository: "https://pkgs.example.com/maven/",
		ProxyURL:        ProxyURLForHost("tok", "host.docker.internal", 41234),
		ScanConfigRoot:  t.TempDir(),
	}
	d, cleanup, err := d.prepareScanConfig(hardenedNet{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := readMavenSettings(t, d)
	for _, want := range []string{"<host>host.docker.internal</host>", "<port>41234</port>"} {
		if !strings.Contains(got, want) {
			t.Errorf("settings missing %q: %s", want, got)
		}
	}
}

func TestPrepareScanConfig_SkipsWhenNotNeeded(t *testing.T) {
	root := t.TempDir()
	d := ContainerRunner{
		ProxyURL:       ProxyURLForHost("tok", "host.docker.internal", 41234),
		ScanConfigRoot: root,
	}
	d, cleanup, err := d.prepareScanConfig(hardenedNet{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if d.mavenSettingsDir != "" {
		t.Errorf("mavenSettingsDir = %q, want empty", d.mavenSettingsDir)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("scan config root not empty: %v", entries)
	}
	joined := strings.Join(d.buildContainerBaseArgs("/work/abs", hardenedNet{}, "/work"), "\x00")
	if strings.Contains(joined, "/scan-config") || strings.Contains(joined, "MAVEN_ARGS") {
		t.Errorf("unexpected scan config args: %q", joined)
	}
}

func TestPrepareScanConfig_HardenedWithoutRepository(t *testing.T) {
	d := ContainerRunner{
		Hardened:       true,
		Egress:         EgressSidecarConfig{Token: "tok"},
		ScanConfigRoot: t.TempDir(),
	}
	d, cleanup, err := d.prepareScanConfig(hardenedNet{proxyEndpoint: "10.89.1.2:3128"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := readMavenSettings(t, d)
	if !strings.Contains(got, "<proxies>") {
		t.Errorf("settings missing proxies: %s", got)
	}
	if strings.Contains(got, "<mirrors>") {
		t.Errorf("settings unexpectedly mirror: %s", got)
	}
}
