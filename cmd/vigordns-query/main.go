package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:15353", "DNS server address")
	typeName := flag.String("type", "A", "DNS record type, for example A or AAAA")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: vigordns-query [-server 127.0.0.1:15353] [-type A] domain")
		os.Exit(2)
	}

	domain := strings.TrimSuffix(strings.TrimSpace(flag.Arg(0)), ".") + "."
	qtype, ok := dns.StringToType[strings.ToUpper(*typeName)]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown DNS type: %s\n", *typeName)
		os.Exit(2)
	}

	request := new(dns.Msg)
	request.SetQuestion(domain, qtype)
	client := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	response, _, err := client.Exchange(request, *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(response)
}
