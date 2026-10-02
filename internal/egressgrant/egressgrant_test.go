package egressgrant

import (
	"reflect"
	"testing"
)

func TestParse_valid(t *testing.T) {
	got, err := Parse([]string{
		"API.Ecosyste.ms:443", "*.example.com:8443", "*.example.com:443", "api.ecosyste.ms:443", "a.example.net:9000", "a.example.net:80",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Grant{
		{Host: "*.example.com", Ports: []string{"443", "8443"}},
		{Host: "a.example.net", Ports: []string{"80", "9000"}},
		{Host: "api.ecosyste.ms", Ports: []string{"443"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse = %+v, want %+v", got, want)
	}
}

func TestParse_invalid(t *testing.T) {
	for _, entry := range []string{
		"", "api.ecosyste.ms", "https://api.ecosyste.ms:443", "api.ecosyste.ms:443/x", "u@api.ecosyste.ms:443",
		"10.0.0.1:443", "127.1:443", "[::1]:443", "::1:443", "localhost:443", "x.localhost:443",
		"*.localhost:443", "*.docker.internal:443", "*.internal:443", "*.INTERNAL:443",
		"host.docker.internal:8080", "Host.Docker.Internal:8080", "a.example.com:0", "a.example.com:65536",
		"a.example.com:http", "a.example.com:0443", "bad_host.example.com:443", " a.example.com:443",
	} {
		if _, err := Parse([]string{entry}); err == nil {
			t.Errorf("Parse(%q) accepted an invalid entry", entry)
		}
	}
}

func TestParse_allowsUnrelatedInternalNames(t *testing.T) {
	for _, entry := range []string{"*.corp.internal:443", "docker.internal:443", "*.example.com:443"} {
		if _, err := Parse([]string{entry}); err != nil {
			t.Errorf("Parse(%q) = %v, want accepted", entry, err)
		}
	}
}

func TestEnvRoundTrip(t *testing.T) {
	grants, err := Parse([]string{"api.ecosyste.ms:443", "*.example.com:443", "*.example.com:8443"})
	if err != nil {
		t.Fatal(err)
	}
	s := Format(grants)
	if want := "*.example.com:443|8443,api.ecosyste.ms:443"; s != want {
		t.Errorf("Format = %q, want %q", s, want)
	}
	back, err := ParseEnv(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, grants) {
		t.Errorf("round trip = %+v, want %+v", back, grants)
	}
	if got, err := ParseEnv(""); err != nil || got != nil {
		t.Errorf("empty env = %v, %v, want nil", got, err)
	}
	for _, bad := range []string{"api.ecosyste.ms", "api.ecosyste.ms:", "10.0.0.1:443", "a.example.com:99999", "*.internal:443"} {
		if _, err := ParseEnv(bad); err == nil {
			t.Errorf("ParseEnv(%q) accepted bad input", bad)
		}
	}
}

func TestHosts(t *testing.T) {
	got := Hosts([]Grant{{Host: "a.example.com", Ports: []string{"443"}}, {Host: "*.b.test", Ports: []string{"80"}}})
	if want := []string{"a.example.com", "*.b.test"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts = %v, want %v", got, want)
	}
}
