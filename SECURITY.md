# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** on this repository rather than in a public issue. Include the version (`dnsentry -version`), your configuration relevant to the problem and steps to reproduce.

## Threat model and hardening

**Web console and API**

- By default the console listens on `127.0.0.1` only and trusts loopback callers. Requests must use `localhost` or an IP address as the `Host`; other names are refused so a web page cannot reach the console through DNS rebinding. State-changing requests must also be same-origin.
- A reverse proxy on the same machine makes remote requests look like loopback. Whenever the console is reachable through a proxy or a non-loopback address, set `DNSENTRY_API_TOKEN` (the service refuses to start on a public address without it) and terminate TLS at the proxy.
- The token is compared in constant time, is never stored in the configuration file or returned by the API, and ten failed attempts within a minute block that client for the rest of the minute.
- The token holder is an administrator. Paths that the service reads or writes (rules file, query log, certificates, trust anchor file) can only be changed through the API to relative paths inside the working directory; use the configuration file for anything else.
- Rule-source and upstream-test features make outgoing requests to addresses chosen by an administrator (this includes internal addresses). Do not give the API token to people you would not trust with network access from the server.

**DNS service**

- An open resolver on a public address can be abused for DNS amplification attacks. If plain DNS is reachable from the internet, set `access.allowed_clients` (and a rate limit), or firewall port 53. Access control and rate limits are keyed on the source address.
- Encrypted DNS listeners (DoT, DoH, DoH3, DoQ, DNSCrypt) need a valid certificate; private keys pasted into the console are stored in the configuration file (mode 0600) and never returned by the API.

**Data at rest**

`data/config.yaml` (and its backups in the same directory) contain secrets such as DNSCrypt keys. Keep the directory private to the service user. Persistent query logs contain client addresses and queried domains.
