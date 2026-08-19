package worker

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestStartScopedEgressProxyClosesListener(t *testing.T) {
	port, cleanup, err := StartScopedEgressProxy(&EgressProxy{
		Allow: []string{"example.com"},
		Token: "scan-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		cleanup()
		t.Fatalf("dial scoped proxy: %v", err)
	}
	_ = conn.Close()
	cleanup()
	if conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("scoped proxy listener remains open after cleanup")
	}
}
