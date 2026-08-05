# Certificates

> ## ⚠️ Everything generated here is development material
>
> The private keys produced by these scripts are **unencrypted** and sit next to
> the certificates they sign. That is appropriate for a local test PKI and for
> nothing else.
>
> **Never deploy them. Never commit them.** `.gitignore` covers `*.key`,
> `*.pem`, `*.crt`, `*.csr` and related patterns, and a CI job fails the build
> if any private key becomes tracked — checking both file names and file
> contents.

## Layout

```
certs/
├── classical/          ECDSA development PKI (git-ignored)
│   ├── ca.crt          development CA certificate
│   ├── ca.key          development CA private key
│   ├── server.crt      server certificate
│   ├── server.key      server private key
│   ├── client.crt      client certificate, for mutual TLS
│   └── client.key      client private key
└── experimental-pq/    EXPERIMENTAL ML-DSA PKI (git-ignored)
    ├── pq-ca.crt
    ├── pq-ca.key
    ├── pq-server.crt
    ├── pq-server.key
    └── size-measurements.json
```

Both directories start empty apart from a `.gitkeep`. Generate their contents on
demand; nothing here is meant to be long-lived.

## Classical PKI

```bash
scripts/generate-classical-certs.sh --with-client
```

Produces an ECDSA P-256 CA and leaf certificates with:

- `basicConstraints` and `keyUsage` marked critical
- `extendedKeyUsage` of `serverAuth` or `clientAuth` as appropriate
- Subject alternative names: `DNS:localhost`, `DNS:pqtls-server`,
  `IP:127.0.0.1`, `IP:::1`
- Key files at mode `600`, certificates at `644`

The `IP:127.0.0.1` SAN matters: the integration tests connect to the address
directly, and a certificate without it would fail hostname verification.

For the `hybrid-p384-mlkem1024` profile, which authenticates with ECDSA P-384:

```bash
scripts/generate-classical-certs.sh --curve secp384r1 --output-dir certs/p384
```

Additional names, for a container or a remote host:

```bash
scripts/generate-classical-certs.sh --extra-san "DNS:pqtls.example.test,IP:10.0.0.5"
```

### Safety behaviour

The script **refuses to overwrite an existing private key** unless `--force` is
given. Silently replacing a key is how a running server ends up with a
certificate that no longer matches it. The check is on the key rather than the
certificate, because the key is the part that cannot be regenerated from
anything else.

It also verifies the chain it produced, and fails if the expected SAN did not
make it into the certificate — a silently missing SAN turns into a confusing
hostname-verification failure much later.

## Experimental post-quantum PKI

```bash
scripts/generate-pq-certs.sh
```

> **⚠️ Experimental, capability-gated, not a deployment path.**
>
> ML-DSA certificates chain to a private CA and are accepted by **nothing**
> outside this project. No public CA issues ML-DSA certificates for general use.
> They exist here to measure certificate and signature size (RQ5) and to test
> whether the TLS stack negotiates them at all.

If the runtime OpenSSL cannot provide ML-DSA, the script **skips with a stated
reason and exits 0**. It never fakes success. Check the printed status.

Use them with the experimental `hybrid-pq-auth` profile only.

## Inspecting what you generated

```bash
# The whole certificate
openssl x509 -in certs/classical/server.crt -noout -text

# Just the SANs
openssl x509 -in certs/classical/server.crt -noout -ext subjectAltName

# Validity dates
openssl x509 -in certs/classical/server.crt -noout -dates

# Verify the chain
openssl verify -CAfile certs/classical/ca.crt certs/classical/server.crt

# Confirm the key matches the certificate
diff <(openssl x509 -in certs/classical/server.crt -noout -pubkey) \
     <(openssl pkey -in certs/classical/server.key -pubout)

# On-the-wire size, for comparison
openssl x509 -in certs/classical/server.crt -outform DER | wc -c
```

## Rotating and cleaning up

Regenerate:

```bash
scripts/generate-classical-certs.sh --with-client --force
```

Remove everything:

```bash
rm -f certs/classical/* certs/experimental-pq/*
touch certs/classical/.gitkeep certs/experimental-pq/.gitkeep
```

Certificates default to 365 days. `scripts/verify-environment.sh` reports the
expiry date, and an expired development certificate produces a clear
`certificate has expired` error rather than a mysterious handshake failure.

## If a key is ever committed

Treat it as compromised, immediately and unconditionally.

1. Regenerate everything with `--force`.
2. Remember that removing the file in a later commit **does not remove it from
   history**. Rewriting history (`git filter-repo`) is required, and anyone who
   already cloned still has the key.
3. If the key ever protected anything real, revoke whatever it authenticated.

This is why the CI check exists, and why it inspects file contents as well as
file names — a key committed under an innocuous name would slip past an
extension check.
