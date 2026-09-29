// Command dnsentry runs the DNS filtering service and its Web console.
package main

import (
	"github.com/teliso/DNSentry/internal/app"
	"github.com/teliso/DNSentry/web"
)

func main() {
	app.Run(web.Console())
}
