package app

import "time"

// Fixed operating parameters. They were configuration keys once; nobody needs
// to tune them for a DNS filter, so they are constants.
const (
	// upstreamTimeout bounds a single upstream exchange.
	upstreamTimeout = 4 * time.Second
	// blockedResponseTTL is the TTL of synthesized blocked and empty answers.
	blockedResponseTTL uint32 = 10
	// queryLogMemoryEntries is how many recent queries the console can page through.
	queryLogMemoryEntries = 1000
	// maxConcurrentQueries caps in-flight queries; excess queries are refused.
	maxConcurrentQueries = 2048
)
