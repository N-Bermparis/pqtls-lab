# Packet-capture analysis

Measuring what a post-quantum handshake actually puts on the wire. This is where
RQ2 lives: the ML-KEM key share enlarges the ClientHello, and the consequences
appear at the packet layer long before they appear in a latency number.

---

> ## ⚠️ Capture only your own test traffic
>
> A packet capture records real traffic. Capture only traffic you generated
> yourself, on a host you control.
>
> Even a TLS capture leaks source and destination addresses, timing, SNI values
> and the full certificate chain. Captures are git-ignored and **must never be
> committed**.

---

## Requirements

```bash
sudo apt-get install tcpdump tshark
```

Capture needs root or `CAP_NET_RAW`. The development container grants
`NET_ADMIN` and `NET_RAW` so this can be done without touching the host.

## Capturing

```bash
sudo scripts/capture-packets.sh \
  --interface lo \
  --port 8443 \
  --output captures/hybrid.pcap \
  --snaplen 0 \
  --duration 60
```

**Always capture with `--snaplen 0`** (whole packets). A truncated capture
produces *wrong* ClientHello sizes rather than an error — the one failure mode
that silently invalidates a size experiment.

The script refuses to overwrite an existing capture, because a benchmark run
that quietly replaced yesterday's capture would be unreproducible and unnoticed.

A useful pattern is to capture the classical and hybrid handshakes separately so
they can be compared directly:

```bash
sudo scripts/capture-packets.sh --interface lo --port 8443 \
  --output captures/classical.pcap --snaplen 0 --duration 30 &
./build/relwithdebinfo/pqtls-client connect --port 8443 \
  --profile classical-x25519 --server-name localhost \
  --ca-certificate certs/classical/ca.crt
wait
```

## Analysing

```bash
python3 tools/pcap_metrics.py captures/hybrid.pcap
python3 tools/pcap_metrics.py captures/hybrid.pcap --json experiments/results/pcap.json
```

Reported per TCP stream:

| Metric | Why it matters |
|---|---|
| ClientHello size | The headline figure. A post-quantum key share is what pushes it past an MTU |
| ServerHello size | Includes the server's key share |
| Handshake segments | More segments means more chances to lose one |
| Total handshake bytes | Bandwidth cost of the handshake |
| Retransmissions | Where loss actually hurt |
| IP fragments | The MTU problem, made visible |
| Time to first application byte | End-to-end handshake cost, as a lower bound |

`tools/pcap_metrics.py` requires `tshark` and **refuses to approximate** without
it. An approximate ClientHello size reported as a measurement would be worse
than no measurement.

## Reading a capture in Wireshark

Useful display filters:

```
tls.handshake.type == 1                 # ClientHello
tls.handshake.type == 2                 # ServerHello
tls.handshake.extensions_key_share_group  # the negotiated group
tcp.analysis.retransmission             # retransmissions
ip.flags.mf == 1 or ip.frag_offset > 0  # fragmentation
tcp.len > 1400                          # segments near a typical MTU
```

To see the ClientHello size directly, select the packet and read the TLS record
length, or add a column for `tls.record.length`.

To compare classical and hybrid, open both captures and compare the ClientHello
frame lengths. The difference is the post-quantum key share.

## What is hard to measure, and why

### Time to first application byte is a lower bound

Under TLS 1.3 the encrypted portion of the handshake is carried in records with
content type **23** — the same as application data. A capture cannot distinguish
the encrypted handshake from the first real application record without the
session keys. `pcap_metrics.py` says so in its output rather than presenting the
figure as exact.

### ClientHello size is not a constant

It depends on which extensions the client sends, not only on the key share. SNI
length, ALPN, supported groups, signature algorithms and session tickets all
contribute. **Measure it; do not compute it from the ML-KEM parameter sizes.**

### Loopback is not a real path

Loopback has no NIC, no driver, no switch and an effectively enormous MTU unless
one is configured. Fragmentation behaviour on loopback does not predict what a
real path with middleboxes and PMTU discovery will do.

---

## Decrypting a capture (development only)

> ### ⚠️ TLS key logging writes session secrets in the clear
>
> This exists so that a *test* handshake can be inspected in Wireshark. It is
> off unless explicitly enabled, it is **refused when `PQTLS_ENV=production`**,
> the destination is git-ignored, and enabling it prints a warning.
>
> Never enable it against traffic that matters, and never commit a key log.

```bash
pqtls-client connect \
  --host 127.0.0.1 --port 8443 \
  --server-name localhost \
  --profile hybrid-x25519-mlkem768 \
  --ca-certificate certs/classical/ca.crt \
  --keylog-file /tmp/pqtls-dev.keylog
```

Then in Wireshark: **Preferences → Protocols → TLS → (Pre)-Master-Secret log
filename**, pointing at that file.

Delete the key log when you are done:

```bash
shred -u /tmp/pqtls-dev.keylog 2>/dev/null || rm -f /tmp/pqtls-dev.keylog
```

Decryption is rarely necessary for this project's questions: handshake sizes,
segment counts and fragmentation are all visible without it. It is useful mainly
for confirming that the framed application protocol is doing what you expect.

## MTU experiments

The interaction most likely to break hybrid TLS in practice.

```bash
for mtu in 576 1280 1500; do
  sudo scripts/apply-netem.sh --interface lo --mtu "$mtu" --yes
  sudo scripts/capture-packets.sh --interface lo --port 18443 \
    --output "captures/mtu-${mtu}.pcap" --snaplen 0 --duration 30 &
  CAPTURE=$!

  python3 scripts/run-benchmarks.py \
    --experiment-id "mtu-${mtu}" \
    --profiles classical-x25519 hybrid-x25519-mlkem768 \
    --connections 100 --concurrency 1

  wait $CAPTURE
  python3 tools/pcap_metrics.py "captures/mtu-${mtu}.pcap" \
    --json "experiments/results/mtu-${mtu}-pcap.json"
  sudo scripts/reset-netem.sh --interface lo
done
```

Compare, across MTUs and profiles: ClientHello size, segment count,
fragmentation count and handshake success rate. An outright failure at a
particular MTU is the headline result and should be reported as such.

See `experiments/definitions/mtu.yaml`.

## Handling captures responsibly

- **Never commit one.** `*.pcap` and `*.pcapng` are git-ignored.
- Capture only locally generated test traffic.
- Delete captures when the analysis is done.
- If a capture must be shared, anonymise it first (`tcprewrite`, `TraceWrangler`)
  and confirm what remains.
- Never share a key log at all.

## Current status

**No packet captures or capture-derived measurements exist in this repository.**

The tooling is implemented; the measurements await an actual run. The example
commands above are the procedure, not a record of results.
