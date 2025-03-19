# ZeroCert

ZeroCert is a decentralized ACME client / DNS-01 server that enables multiple hosts to obtain and renew SSL/TLS certificates for the same domain without relying on central storage. It leverages DNS glue records for peer discovery and parallel querying, removing the need for manual coordination.

This approach is suitable for a small number of nodes deployed in a simple environment with no dependencies. All participating hosts must be listed in the glue record, which limits this technique to small installations.

## Features

- **Decentralized ACME Client** – Eliminates central storage / management for TLS certificates.
- **DNS-01 Challenge Handling** – Uses glue records to discover other servers handling the domain and query all peers in parallel to complete the TXT query.
- **Wildcard Domain Support** — Use DNS-01 challenge to enable wildcard certificate support.
- **Certificate Caching & Retrieval** – New hosts attempt to fetch the latest certificate from all peers over HTTPS / mTLS. The mTLS authentication is automatically derived from the ACME private key and requires zero configuration.

## How It Works

1. **Peer Discovery** – The client looks up the glue records for the domain to identify other hosts.
2. **DNS-01 Challenge Coordination** – Instead of using a central database, peers query each other in parallel for the required TXT record.
3. **Certificate Retrieval on Startup** – On host startup, it first attempts to fetch an existing certificate from all peers via glue discovery over HTTPS using mTLS and keep the most recent in its cache.
4. **Automated Renewal** – Certificates are automatically renewed and distributed among participating servers.

## Installation

```sh
go get github.com/rs/zerocert
```

## Usage

Given a domain `example.com` delegated to a list of hosts running the code below, configure the IP of each hosts into the glue record for `example.com`.

```go
m := zerocert.Manager{
    Domain: "example.com",
    Email: "user@exemple.com",
    Reg: "https://acme-v02.api.letsencrypt.org/acme/acct/1234",
    Key: []byte("-----BEGIN EC PRIVATE KEY-----
MHcCA...w==
-----END EC PRIVATE KEY-----"),
    CacheFile: "/var/cache/example-cert.pem",
}

d := dns.Server{
    PacketConn: m.NewDNSListener(nil),
    Handler: ...
}
defer ds.Shutdown()
go func() {
    err := ds.ActivateAndServe()
    done <- err
}()

l, err := net.Listen("tcp", ":443")
defer l.Close()
if err != nil {
    return err
}
tl := m.NewTLSListener(l)

s := http.Server {
    Handler: ...
}

go func() {
    if err := http.Serve(tl, s); err != nil {
        log.Print(err)
    }
}()

m.LoadOrRefresh()

for {
    select {
    case <-time.After(24 * time.Hour):
        s.loadOrRefresh()
    }
}
```

### ACME Account Information

To get ACME user information, run:

```sh
./register.sh
```

## License

MIT License

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.
