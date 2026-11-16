# CoreDNS overhead benchmark

`scripts/bench.sh` runs the real CoreDNS binary locally and compares four
cases at fixed query rates:

| Case | CoreDNS config |
|---|---|
| A | no dnstap (baseline) |
| B | `dnstap ... full` -> dns-auditor (normal operation) |
| C | `dnstap ... full` -> nothing listening (auditor down) |
| D | `dnstap ... full` -> a sink that handshakes and never reads (auditor stuck) |

The query mix is shaped like an `ndots:5` cluster: about 75% NXDOMAIN
search-list expansions, the rest answered. Cases are interleaved (A B C D,
three times) and medians are reported.

## Results (2026-11-16)

CoreDNS 1.14.7, 4 vCPU WSL2 VM, 20 s per run, 3 runs per cell.
`cpu%` is the CoreDNS process as a share of one core.

| Case | qps | DNS failures | p50 ms | p99 ms (median / min) | CoreDNS cpu% | CoreDNS RSS max MiB | auditor RSS MiB | auditor drops |
|---|---|---|---|---|---|---|---|---|
| A |  150 | 0 | 0.51 | 1.07 / 0.79 |  5.4 | 55.0 | – | – |
| A |  750 | 0 | 0.44 | 2.19 / 0.66 | 21.9 | 56.5 | – | – |
| A | 1500 | 0 | 0.39 | 3.89 / 1.15 | 34.8 | 57.4 | – | – |
| B |  150 | 0 | 0.55 | 0.80 / 0.75 |  7.5 | 55.5 | 36.5 | 0 |
| B |  750 | 0 | 0.47 | 10.17 / 0.68 | 26.3 | 57.6 | 38.2 | 0 |
| B | 1500 | 0 | 0.40 | 3.91 / 1.21 | 40.6 | 57.8 | 39.3 | 0 |
| C |  150 | 0 | 0.55 | 0.79 / 0.76 |  7.4 | 55.2 | – | – |
| C |  750 | 0 | 0.43 | 0.69 / 0.66 | 25.4 | 57.0 | – | – |
| C | 1500 | 0 | 0.37 | 1.31 / 1.14 | 37.8 | 57.5 | – | – |
| D |  150 | 0 | 0.54 | 0.78 / 0.75 |  7.2 | 56.0 | – | – |
| D |  750 | 0 | 0.43 | 1.15 / 0.87 | 26.1 | 62.3 | – | – |
| D | 1500 | 0 | 0.34 | 1.67 / 1.27 | 35.7 | 66.5 | – | – |

Raw data: `docs/results/bench-2026-11-16.json`.

## Reading the numbers

- **No DNS failures in any of the 36 runs**, including when the receiver is
  down (C) or stuck (D). CoreDNS's dnstap output is asynchronous; when the
  receiver does not read, CoreDNS buffers (RSS +5 to +9 MiB in D) and drops.
  It does not slow down answers.
- **Median latency is unchanged** (p50 within ±0.05 ms).
- **p99 is dominated by VM noise.** The baseline alone ranged from 0.66 ms to
  19.6 ms between runs at 750 qps. Comparing the best run of each case, the
  difference is at most 0.2 ms. Confirm tail latency on a real cluster with
  `coredns_dns_request_duration_seconds`.
- **CPU: dnstap with `full` costs CoreDNS about +2 / +4 / +6 points of one core
  at 150 / 750 / 1500 qps** (+38% / +20% / +17% relative). B, C and D cost
  about the same, so this is CoreDNS serializing dnstap messages, not
  dns-auditor. The `full` flag is required because the response code is only
  in the wire message, and CoreDNS sends both queries and responses.
- **dns-auditor itself:** about 37 MiB RSS and zero dropped events at 1,500 qps
  (about 3,000 dnstap frames/s).

## Limits of this setup

- The `template` plugin stands in for the `kubernetes` plugin, so the absolute
  CPU numbers are lower than in a cluster. The dnstap cost per query is what
  carries over.
- The generator, CoreDNS and dns-auditor share one 4 vCPU VM over loopback.
