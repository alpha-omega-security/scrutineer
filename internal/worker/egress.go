// This file re-exports github.com/alpha-omega-security/harness/egress under
// the names the rest of scrutineer already uses, so the swap is one file
// rather than forty call sites. The package-name prefix that would be
// redundant with the egress package (EgressProxy vs egress.Proxy) is kept
// here for now; a follow-up rename can drop it once the harness core PR has
// landed and the churn settles.
package worker

import (
	"context"

	"github.com/alpha-omega-security/harness/egress"
)

const (
	HostGatewayAlias        = egress.HostGatewayAlias
	SidecarListenFirstIface = egress.ListenFirstIface
)

var (
	DefaultEgressAllow  = egress.DefaultAllow
	HardenedEgressAllow = egress.HardenedAllow
)

type EgressProxy = egress.Proxy

func StartEgressProxy(p *EgressProxy) (int, error)        { return egress.Start(p) }
func ServeEgressProxy(p *EgressProxy, addr string) error  { return egress.Serve(p, addr) }
func NewProxyToken() string                               { return egress.NewToken() }
func ProxyURLForHost(token, host string, port int) string { return egress.ProxyURL(token, host, port) }
func ProxyURLForEndpoint(token, endpoint string) string   { return egress.EndpointURL(token, endpoint) }
func FirstIfaceIPv4() (string, error)                     { return egress.FirstIfaceIPv4() }

func WaitHostAPIReachable(ctx context.Context, host, port string) error {
	return egress.WaitHostAPIReachable(ctx, host, port)
}

func VerifyUpstreamDNS(ctx context.Context, allow []string) error {
	return egress.VerifyUpstreamDNS(ctx, allow)
}
