# Xelay TC eBPF Backend

This is the v2 backend for Xelay. It keeps the user-facing shape of the v1
nftables backend, but moves the dataplane into TC eBPF so forwarding state lives
in BPF programs and maps instead of nftables, iptables, conntrack, Docker chains,
UFW, firewalld, or kube-proxy rule order.

The first milestone is an IPv4 TCP/UDP forwarding MVP:

- attach one TC ingress classifier to `host_interface`
- populate BPF maps from the existing Xelay config shape
- rewrite IPv4 TCP/UDP packets in the TC program
- track forward and reverse flows in BPF LRU maps
- expose per-rule/protocol/direction packet and byte counters
- provide `apply`, `run`, `status`, `check`, and `clean`
- parse quota and connection-limit fields, but defer enforcement

The eBPF crate under `ebpf/` targets `bpfel-unknown-none` and is intentionally
not a workspace member for normal host builds.

## Layout

```text
tc-ebpf-backend/
  src/                 userspace controller
  src/dataplane.rs     Aya loader, TC attach/detach, BPF map IO
  src/model.rs         map keys/values shared with the eBPF program
  src/reconcile.rs     apply/run/status/check/clean orchestration
  ebpf/src/main.rs     TC classifier program
```

## Commands

```bash
xelay-tc-ebpf --config config.json check
xelay-tc-ebpf --config config.json apply
xelay-tc-ebpf --config config.json run
xelay-tc-ebpf --config config.json status
xelay-tc-ebpf --config config.json clean
```

- `check` verifies root status, interface existence, `/sys/fs/bpf`, BPF object
  existence, and rule count.
- `apply` loads the BPF object, creates `clsact` on `host_interface`, attaches
  the TC ingress classifier, writes rule/settings maps, persists state, and exits.
- `run` repeats reconciliation at `poll_interval_secs`; v2 currently always uses
  run mode by default because BPF counters should be sampled continuously.
- `status` reads BPF counters and combines them with persisted state.
- `clean` detaches the v2 TC ingress program from `host_interface`.

## Config

The MVP config is intentionally close to v1:

```json
{
  "host_interface": "eth0",
  "bpf_object_path": "/usr/lib/xelay/xelay-tc-ebpf.o",
  "state_path": "/var/lib/xelay/tc-ebpf-state.json",
  "poll_interval_secs": 2,
  "rules": [
    {
      "name": "svc-5000",
      "listen_port": 5000,
      "protocols": ["tcp", "udp"],
      "target_host": "114.111.191.26",
      "target_port": 2616,
      "enabled": true
    }
  ]
}
```

Important MVP constraints:

- `target_host` must be an IPv4 address, not a DNS name.
- duplicate `(listen_port, protocol)` listeners are rejected.
- `quota_in`, `quota_out`, `max_tcp_connections`, and `max_udp_flows` are
  accepted for config compatibility but not enforced yet.
- `host_interface` is both the public ingress interface and the source address
  used for SNAT in the current packet rewrite model.

## How The Controller Works

The userspace controller owns all slow-path work:

1. Parse and validate JSON config.
2. Load persisted counter/runtime state from `state_path`.
3. Read current BPF counters from `COUNTERS`.
4. Mark each rule as enabled, disabled by config, or enabled with deferred limits.
5. Load the eBPF object from `bpf_object_path`.
6. Create a `clsact` qdisc on `host_interface`.
7. Attach `xelay_tc_ingress` to TC ingress.
8. Populate `RULES` with one entry per `(protocol, listen_port)`.
9. Populate `SETTINGS` with the current IPv4 address of `host_interface`.
10. Save state.

The controller does not install nftables, iptables, conntrack, namespace, or veth
rules in v2.

## BPF Maps

`RULES`

Keyed by `(protocol, listen_port)`. The value contains:

- numeric rule id, which indexes into the config rule order
- enabled flag
- backend IPv4 address
- backend port
- original listen port

`SETTINGS`

Small configuration map. Key `0` currently stores the host interface IPv4
address in network byte order. The eBPF program uses it as the SNAT source IP.

`COUNTERS`

Keyed by `(rule_id, protocol, direction)`. Direction `0` is client-to-backend
and direction `1` is backend-to-client. The controller sums TCP and UDP samples
for each rule before rendering status.

`FLOWS` and `REVERSE_FLOWS`

LRU maps used by the eBPF program to remember active packet translations. The
forward map records client-to-backend observations. The reverse map lets replies
from a backend be rewritten back to the original public listener and client.

## Packet Path

The TC classifier is attached to ingress on `host_interface`. It sees packets
after the NIC receives them and before normal host routing makes its forwarding
decision.

### Client To Backend

Example config:

```json
{
  "listen_port": 6000,
  "protocols": ["tcp"],
  "target_host": "163.53.52.70",
  "target_port": 6000
}
```

Packet before TC:

```text
client_ip:client_port -> host_public_ip:6000
```

The eBPF program:

1. Parses Ethernet, IPv4, TCP/UDP headers.
2. Looks up `RULES[(tcp, 6000)]`.
3. Increments the inbound counter.
4. Stores flow state for reverse rewriting.
5. Rewrites:
   - source IP: `client_ip` to `host_interface_ip`
   - destination IP: `host_public_ip` to `163.53.52.70`
   - destination port: `6000` to `target_port`
6. Updates IPv4 and TCP/UDP checksums.
7. Returns `TC_ACT_OK`, so the kernel continues routing the rewritten packet.

Packet after TC:

```text
host_interface_ip:client_port -> 163.53.52.70:6000
```

### Backend To Client

Packet before TC:

```text
163.53.52.70:6000 -> host_interface_ip:client_port
```

The eBPF program:

1. Looks up `REVERSE_FLOWS[(backend_ip, backend_port, client_port, protocol)]`.
2. Increments the outbound counter.
3. Rewrites:
   - source IP: backend IP to original public listener IP
   - source port: backend port to original listen port
   - destination IP: `host_interface_ip` to original client IP
   - destination port: `client_port` to original client port
4. Updates IPv4 and TCP/UDP checksums.
5. Returns `TC_ACT_OK`.

Packet after TC:

```text
host_public_ip:6000 -> client_ip:client_port
```

## Current MVP Limitations

The v2 code is a starting point, not full production parity with v1 yet.

- NAT source port allocation is not implemented. The MVP keeps the client source
  port as the host-side NAT port, so two clients with the same source port going
  to the same backend can collide.
- Quotas and connection/flow limits are parsed and surfaced in status, but not
  enforced in eBPF yet.
- The eBPF object build needs a Rust eBPF toolchain with `bpfel-unknown-none`
  and `-Z build-std=core`.
- The TC program currently relies on normal kernel routing after packet rewrite;
  explicit `bpf_redirect`/FIB redirect can be added after the base rewrite path
  is verified on real hosts.
- IPv6 is not supported.

## Build

Build the userspace controller from the repository root:

```bash
cargo build -p xelay-tc-ebpf
```

Build the eBPF object separately with an Aya-compatible Rust eBPF toolchain, then
install it where the controller can load it. Current Rust toolchains normally need
nightly `-Z build-std=core` for `bpfel-unknown-none`:

```bash
cargo build --manifest-path tc-ebpf-backend/ebpf/Cargo.toml \
  --target bpfel-unknown-none --release -Z build-std=core
sudo install -m 0644 \
  tc-ebpf-backend/ebpf/target/bpfel-unknown-none/release/xelay_tc_ebpf \
  /usr/lib/xelay/xelay-tc-ebpf.o
```

Override the object path with `--bpf-object` when needed:

```bash
sudo target/debug/xelay-tc-ebpf \
  --config tc-ebpf-backend/config.example.json \
  --bpf-object /path/to/xelay-tc-ebpf.o \
  apply
```

## Operational Checks

Useful Linux inspection commands:

```bash
tc qdisc show dev eth0
tc filter show dev eth0 ingress
sudo bpftool prog show
sudo bpftool map show
sudo bpftool map dump name RULES
sudo bpftool map dump name COUNTERS
```

Use `status` for the controller view:

```bash
sudo xelay-tc-ebpf --config config.json status
```
