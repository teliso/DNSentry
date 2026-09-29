// Command dnsentry runs the DNS filtering service and its Web console.
package main

import (
	"flag"

	"github.com/teliso/DNSentry/internal/app"
	"github.com/teliso/DNSentry/web"
)

func main() {
	config := flag.String("config", "data/config.yaml", "path to the YAML configuration file")
	flag.Parse()
	app.Run(web.Console(), *config)
}
