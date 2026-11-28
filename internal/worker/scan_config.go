package worker

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// ScanConfigMountDir is where a scan's generated config directory is mounted
// read-only.
const ScanConfigMountDir = "/scan-config"

// mavenSettingsPath is relative to the scan config dir.
const mavenSettingsPath = "maven/settings.xml"

// Generated scan config is owner-only, like other host state the runner
// writes.
const (
	scanConfigDirPerm  = 0o700
	scanConfigFilePerm = 0o600
)

// prepareScanConfig writes this scan's generated config files and returns a
// runner that mounts them, plus a cleanup that removes them. Maven settings
// are written when a maven repository is configured or the scan is hardened.
// Hardened scans always get them because Maven ignores HTTPS_PROXY and has no
// other route out. Non-hardened scans without a maven repository keep the
// image's own Maven settings.
func (d ContainerRunner) prepareScanConfig(hnet hardenedNet) (ContainerRunner, func(), error) {
	noop := func() {}
	if d.MavenRepository == "" && !d.Hardened {
		return d, noop, nil
	}
	content, err := mavenSettings(d.MavenRepository, d.scanProxyURL(hnet))
	if err != nil {
		return d, noop, fmt.Errorf("render maven settings: %w", err)
	}
	root := d.ScanConfigRoot
	if root == "" {
		root = os.TempDir()
	}
	if err := os.MkdirAll(root, scanConfigDirPerm); err != nil {
		return d, noop, fmt.Errorf("create scan config root: %w", err)
	}
	dir, err := os.MkdirTemp(root, "scan-")
	if err != nil {
		return d, noop, fmt.Errorf("create scan config dir: %w", err)
	}
	file := filepath.Join(dir, filepath.FromSlash(mavenSettingsPath))
	if err := os.MkdirAll(filepath.Dir(file), scanConfigDirPerm); err != nil {
		_ = os.RemoveAll(dir)
		return d, noop, fmt.Errorf("write maven settings: %w", err)
	}
	if err := os.WriteFile(file, content, scanConfigFilePerm); err != nil {
		_ = os.RemoveAll(dir)
		return d, noop, fmt.Errorf("write maven settings: %w", err)
	}
	d.mavenSettingsDir = dir
	return d, func() { _ = os.RemoveAll(dir) }, nil
}

// xmlEscape escapes s for use as XML character data.
func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // writing to a bytes.Buffer cannot fail
	return b.String()
}

// mavenSettings renders a Maven global settings file. A non-empty mirrorURL
// adds a mirror of central. A non-empty proxyURL adds an https proxy entry,
// because Maven ignores HTTPS_PROXY. Errors never include proxyURL since it
// carries the scan's proxy credential.
func mavenSettings(mirrorURL, proxyURL string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\">\n")
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, errors.New("proxy URL is not parseable")
		}
		port := u.Port()
		if port == "" {
			return nil, errors.New("proxy URL has no port")
		}
		if _, err := strconv.Atoi(port); err != nil {
			return nil, errors.New("proxy URL port is not a number")
		}
		b.WriteString("  <proxies>\n    <proxy>\n")
		b.WriteString("      <id>scrutineer-egress</id>\n")
		b.WriteString("      <active>true</active>\n")
		b.WriteString("      <protocol>https</protocol>\n")
		b.WriteString("      <host>" + xmlEscape(u.Hostname()) + "</host>\n")
		b.WriteString("      <port>" + xmlEscape(port) + "</port>\n")
		if u.User != nil {
			b.WriteString("      <username>" + xmlEscape(u.User.Username()) + "</username>\n")
			if pw, ok := u.User.Password(); ok {
				b.WriteString("      <password>" + xmlEscape(pw) + "</password>\n")
			}
		}
		b.WriteString("    </proxy>\n  </proxies>\n")
	}
	if mirrorURL != "" {
		b.WriteString("  <mirrors>\n    <mirror>\n")
		b.WriteString("      <id>scrutineer-package-repository</id>\n")
		b.WriteString("      <mirrorOf>central</mirrorOf>\n")
		b.WriteString("      <url>" + xmlEscape(mirrorURL) + "</url>\n")
		b.WriteString("    </mirror>\n  </mirrors>\n")
	}
	b.WriteString("</settings>\n")
	return b.Bytes(), nil
}
