package app

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/miekg/dns"

	"github.com/teliso/DNSentry/internal/dnsname"
)

// UpstreamRoute sends queries for a set of domains (and their subdomains) to
// dedicated upstreams instead of the default ones, e.g. an internal domain to
// the router or a corporate resolver.
type UpstreamRoute struct {
	Name      string   `json:"name,omitempty" yaml:"name,omitempty"`
	Domains   []string `json:"domains" yaml:"domains"`
	Upstreams []string `json:"upstreams" yaml:"upstreams"`
}

const (
	maxUpstreamRoutes = 64
	maxRouteDomains   = 64
	maxRouteUpstreams = 8
)

// validateUpstreamRoutes normalizes routes in place and rejects invalid or
// ambiguous ones.
func validateUpstreamRoutes(routes []UpstreamRoute) error {
	if len(routes) > maxUpstreamRoutes {
		return fmt.Errorf("upstream_routes must contain at most %d routes", maxUpstreamRoutes)
	}
	seen := make(map[string]int)
	for index := range routes {
		route := &routes[index]
		route.Name = strings.TrimSpace(route.Name)
		if len([]rune(route.Name)) > 64 {
			return fmt.Errorf("upstream_routes[%d] name is too long", index)
		}
		if len(route.Domains) == 0 || len(route.Domains) > maxRouteDomains {
			return fmt.Errorf("upstream_routes[%d] needs between 1 and %d domains", index, maxRouteDomains)
		}
		if len(route.Upstreams) == 0 || len(route.Upstreams) > maxRouteUpstreams {
			return fmt.Errorf("upstream_routes[%d] needs between 1 and %d upstreams", index, maxRouteUpstreams)
		}
		for domainIndex, domain := range route.Domains {
			domain = strings.TrimPrefix(strings.TrimPrefix(dnsname.Normalize(domain), "*"), ".")
			if !dnsname.Valid(domain) {
				return fmt.Errorf("upstream_routes[%d].domains[%d] %q is not a valid domain", index, domainIndex, route.Domains[domainIndex])
			}
			if previous, exists := seen[domain]; exists {
				return fmt.Errorf("domain %q is routed twice (upstream_routes[%d] and [%d])", domain, previous, index)
			}
			seen[domain] = index
			route.Domains[domainIndex] = domain
		}
		for upstreamIndex, address := range route.Upstreams {
			normalized, err := validateUpstream(address, false)
			if err != nil {
				return fmt.Errorf("invalid upstream_routes[%d].upstreams[%d]: %w", index, upstreamIndex, err)
			}
			route.Upstreams[upstreamIndex] = normalized
		}
	}
	return nil
}

func upstreamRoutesEqual(left, right []UpstreamRoute) bool {
	return reflect.DeepEqual(left, right)
}

type activeRoute struct {
	config UpstreamRoute
	pool   *UpstreamPool
}

// routeTable resolves a query name to the most specific route.
type routeTable struct {
	routes   []*activeRoute
	byDomain map[string]*activeRoute
}

func (t *routeTable) lookup(name string) *activeRoute {
	if t == nil || len(t.byDomain) == 0 {
		return nil
	}
	for candidate := dnsname.Normalize(name); candidate != ""; candidate = dnsname.Parent(candidate) {
		if route, ok := t.byDomain[candidate]; ok {
			return route
		}
	}
	return nil
}

// buildRouteTable compiles routes, reusing the upstream pools (and so their
// health state) of routes that did not change.
func buildRouteTable(routes []UpstreamRoute, previous *routeTable) *routeTable {
	reusable := make(map[string]*UpstreamPool)
	if previous != nil {
		for _, route := range previous.routes {
			reusable[strings.Join(route.config.Upstreams, "\n")] = route.pool
		}
	}
	table := &routeTable{byDomain: make(map[string]*activeRoute)}
	for _, config := range routes {
		key := strings.Join(config.Upstreams, "\n")
		pool, ok := reusable[key]
		if !ok {
			pool = NewUpstreamPool(config.Upstreams)
		}
		route := &activeRoute{config: config, pool: pool}
		table.routes = append(table.routes, route)
		for _, domain := range config.Domains {
			table.byDomain[domain] = route
		}
	}
	return table
}

// RouteStatus is the API view of a route and the health of its upstreams.
type RouteStatus struct {
	Name      string           `json:"name,omitempty"`
	Domains   []string         `json:"domains"`
	Upstreams []UpstreamHealth `json:"upstreams"`
}

func (s *DNSServer) routeStatus() []RouteStatus {
	table := s.routes.Load()
	if table == nil {
		return []RouteStatus{}
	}
	result := make([]RouteStatus, 0, len(table.routes))
	for _, route := range table.routes {
		result = append(result, RouteStatus{Name: route.config.Name, Domains: route.config.Domains, Upstreams: route.pool.Health()})
	}
	return result
}

func (s *DNSServer) setUpstreamRoutes(routes []UpstreamRoute) {
	s.routes.Store(buildRouteTable(routes, s.routes.Load()))
}

// routeFor returns the route that handles the question of request, if any.
func (s *DNSServer) routeFor(request *dns.Msg) *activeRoute {
	if len(request.Question) == 0 {
		return nil
	}
	return s.routes.Load().lookup(request.Question[0].Name)
}

var errNoRouteUpstream = errors.New("no healthy upstream for routed domain")

// exchangeRoute resolves request through the route's upstreams only. Routed
// names are never sent to the default upstreams, which would leak internal
// names to a public resolver; failure yields an error (SERVFAIL for clients).
func (s *DNSServer) exchangeRoute(config Config, route *activeRoute, request *dns.Msg) (*dns.Msg, string, error) {
	candidates := route.pool.Candidates()
	if len(candidates) == 0 {
		return nil, "", errNoRouteUpstream
	}
	switch config.UpstreamMode {
	case upstreamModeParallel:
		return s.exchangeParallel(request, candidates, route.pool)
	case upstreamModeFastestAddr:
		return s.exchangeFastestAddr(request, candidates, route.pool)
	default:
		return s.exchangeLoadBalance(request, candidates, route.pool)
	}
}
