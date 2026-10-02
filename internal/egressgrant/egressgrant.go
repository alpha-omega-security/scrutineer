// Package egressgrant parses and validates the per-skill host:port egress
// grants an operator configures. It is a leaf package so the config loader, the
// worker and the proxy sidecar all apply one set of rules.
package egressgrant

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/alpha-omega-security/harness/egress"
)

const (
	minTCPPort        = 1
	maxTCPPort        = 65535
	portSep           = "|"
	hostPortSep       = ":"
	entrySep          = ","
	localhostSuffix   = ".localhost"
	localhostHostname = "localhost"
)

var hostPattern = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// Grant is one operator-granted destination: a hostname (or *.domain)
// reachable only on Ports.
type Grant struct {
	Host  string
	Ports []string
}

// Parse turns "host:port" entries into grants. Entries for the same host merge
// and the result is sorted and deduplicated so the formatted policy is stable.
func Parse(entries []string) ([]Grant, error) {
	byHost := map[string][]string{}
	for _, entry := range entries {
		host, port, err := parseEntry(entry)
		if err != nil {
			return nil, err
		}
		byHost[host] = append(byHost[host], port)
	}
	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	grants := make([]Grant, 0, len(hosts))
	for _, host := range hosts {
		ports := byHost[host]
		slices.SortFunc(ports, func(a, b string) int {
			na, _ := strconv.Atoi(a)
			nb, _ := strconv.Atoi(b)
			return na - nb
		})
		grants = append(grants, Grant{Host: host, Ports: slices.Compact(ports)})
	}
	return grants, nil
}

func parseEntry(entry string) (host, port string, err error) {
	if strings.TrimSpace(entry) != entry || entry == "" || strings.Contains(entry, "://") || strings.ContainsAny(entry, "/@ ") {
		return "", "", fmt.Errorf("egress grant %q must be host:port without a scheme, path or userinfo", entry)
	}
	host, port, ok := strings.Cut(entry, hostPortSep)
	if !ok || strings.Contains(port, hostPortSep) {
		return "", "", fmt.Errorf("egress grant %q must be a DNS hostname and a port (host:port)", entry)
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < minTCPPort || n > maxTCPPort || strconv.Itoa(n) != port {
		return "", "", fmt.Errorf("egress grant %q has an invalid port (want %d to %d)", entry, minTCPPort, maxTCPPort)
	}
	host = strings.ToLower(host)
	// All digits and dots catches shorthand IPv4 forms such as "127.1" or
	// "2130706433" that a lenient resolver would accept although ParseIP does not.
	if !hostPattern.MatchString(host) || net.ParseIP(host) != nil || strings.Trim(host, "0123456789.") == "" {
		return "", "", fmt.Errorf("egress grant %q must name a DNS hostname or *.domain, not an IP address", entry)
	}
	if coversHostService(host) {
		return "", "", fmt.Errorf("egress grant %q names a local or host address, which grants cannot cover", entry)
	}
	return host, port, nil
}

// coversHostService reports whether host is, or as a wildcard covers, a name
// that reaches services on the machine running the scan.
func coversHostService(host string) bool {
	if strings.HasSuffix(host, localhostSuffix) {
		return true
	}
	for _, name := range []string{egress.HostGatewayAlias, localhostHostname} {
		if host == name || egress.HostAllowed([]string{host}, name) {
			return true
		}
	}
	return false
}

// Format renders grants as "host:p1|p2,host2:p" for the sidecar environment and
// the scan record. The output is deterministic for a given set of grants as
// Parse sorts them.
func Format(g []Grant) string {
	parts := make([]string, 0, len(g))
	for _, grant := range g {
		parts = append(parts, grant.Host+hostPortSep+strings.Join(grant.Ports, portSep))
	}
	return strings.Join(parts, entrySep)
}

// ParseEnv is the inverse of Format. An empty string means no grants.
func ParseEnv(s string) ([]Grant, error) {
	var entries []string
	for item := range strings.SplitSeq(s, entrySep) {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		host, ports, ok := strings.Cut(item, hostPortSep)
		if !ok {
			return nil, fmt.Errorf("egress grant %q must be host:port", item)
		}
		for port := range strings.SplitSeq(ports, portSep) {
			entries = append(entries, host+hostPortSep+port)
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return Parse(entries)
}

// Hosts lists the granted host patterns in order.
func Hosts(g []Grant) []string {
	hosts := make([]string, 0, len(g))
	for _, grant := range g {
		hosts = append(hosts, grant.Host)
	}
	return hosts
}
