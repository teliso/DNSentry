# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** on this repository rather than in a public issue. Include the version (`dnsentry -version`), your configuration relevant to the problem and steps to reproduce.

## Threat model and hardening

**Web console and API**

- By default the console listens on `127.0.0.1` only and trusts loopback callers. Requests must use `localhost` or an IP address as the `Host`; other names are refused so a web page cannot reach the console through DNS rebinding. State-changing requests must also be same-origin.
- A reverse proxy on the same machine makes remote requests look like loopback. Whenever the console is reachable through a proxy or a non-loopback address, set `DNSENTRY_API_TOKEN` (the service refuses to start on a public address without it) and terminate TLS at the proxy.
- A console password can be set from the console (Settings → Console login). The password is stored as a bcrypt hash in `auth.json` next to the configuration file (mode 0600). Once set, every console request needs a session, including loopback ones; the session is a random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie (7 days; only its hash is kept, in memory, so a restart signs everybody out). Sign-in is same-origin only, and failed sign-ins and wrong "current password" entries are throttled like token failures. Changing the password signs all other browsers out. A password alone satisfies the "public listen address needs authentication" rule.
- The console speaks plain HTTP unless HTTPS is turned on (Settings → Console HTTPS, `web.tls`). On a network you do not fully trust, plain HTTP sends the password and the session cookie unencrypted: enable HTTPS, put the console behind an HTTPS reverse proxy, or keep it on loopback. The certificate can be created self-signed next to the configuration file, shared with the encrypted DNS service, or supplied separately; browsers cannot verify it, so compare the SHA-256 fingerprint shown in the console, or supply your own certificate. The cookie is marked `Secure` whenever the request arrives over TLS, and the service logs a warning when it listens publicly over plain HTTP.
- Known limits of the login: the throttle is per client address, so behind a reverse proxy every visitor shares one address (a live session is still accepted while the address is throttled); cookies are not isolated by port, so another web application on the same host name can see the `dnsentry_session` cookie, and DNSentry should not share a host name with software you do not trust; sessions are not bound to an IP address. `X-Forwarded-Proto: https` is honoured (for the cookie's `Secure` flag) only from loopback.
- A login can also be set by editing the configuration file (`web.auth.username` / `web.auth.password`, plain text of any length or a bcrypt hash). At the next start it is converted to a hash in `auth.json` and the `web.auth` block is removed from the file, so the plain text does not stay on disk or enter the configuration history. The 8-character minimum applies to the console only.
- Forgotten password: stop the service, delete `auth.json`, start it again (the console is then loopback-only until a new password is set).
- The token is compared in constant time, is never stored in the configuration file or returned by the API, and ten failed attempts within a minute block that client for the rest of the minute.
- The token holder is an administrator. Paths that the service reads or writes (rules file, query log, certificates, trust anchor file) can only be changed through the API to relative paths inside the working directory; use the configuration file for anything else.
- Notification webhooks are chosen by an administrator and are called by the server without following redirects. Their URLs often contain secrets; they are stored in the configuration file, and therefore appear in exports and history versions.
- Rule-source and upstream-test features make outgoing requests to addresses chosen by an administrator (this includes internal addresses). Do not give the API token to people you would not trust with network access from the server.

**DNS service**

- An open resolver on a public address can be abused for DNS amplification attacks. If plain DNS is reachable from the internet, set `access.allowed_clients` (and a rate limit), or firewall port 53. Access control and rate limits are keyed on the source address.
- Encrypted DNS listeners (DoT, DoH, DoH3, DoQ, DNSCrypt) need a valid certificate; private keys pasted into the console are stored in the configuration file (mode 0600) and never returned by the API.

**Data at rest**

`data/config.yaml` (and its backups in the same directory) contain secrets such as DNSCrypt keys. Keep the directory private to the service user. Persistent query logs contain client addresses and queried domains.
