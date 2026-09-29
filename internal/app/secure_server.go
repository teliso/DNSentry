package app

import "time"

const (
	secureDNSMaxMessageSize  = 65535
	secureStreamTimeout      = 15 * time.Second
	secureDoQIdleTimeout     = 90 * time.Second
	secureDoH3IdleTimeout    = 90 * time.Second
	secureDoH3RequestTimeout = 15 * time.Second
)
