# Xelay Tool Summary

`xelay` is a Rust CLI for namespace-isolated Linux TCP/UDP port forwarding.

It is designed to run as a privileged controller on Linux. It reads a JSON config, creates or updates a dedicated network namespace, installs nftables NAT/filter rules, tracks traffic counters, enforces quotas and connection limits, and reports operator status.

## Commands

```bash
xelay
xelay --config config.json apply
xelay --config config.json run
xelay --config config.json status
xelay --config config.json check
```

- no subcommand: loads config from `./config.json` or `/etc/config/xelay/config.json`, then chooses `apply` or `run` automatically.
- `apply`: performs one reconciliation pass, then exits.
- `run`: continuously reconciles at the configured polling interval.
- `status`: prints rule state, byte counters, quotas, and flow counts.
- `check`: verifies required external Linux tools are available.

Automatic mode chooses `run` when any enabled rule defines `quota_in`, `quota_out`, `max_tcp_connections`, or `max_udp_flows`. If no enabled rule has limits, it performs `apply` once.

## Runtime Dependencies

`xelay` shells out to standard Linux networking tools:

- `ip`
- `nft`
- `conntrack`
- `sysctl`

It assumes IPv4-only operation and should normally be run as root.

## How Forwarding Works

A rule maps a host listen port to a backend target. For example:

```json
{
  "listen_port": 5000,
  "protocols": ["tcp", "udp"],
  "target_host": "114.111.191.26",
  "target_port": 2616
}
```

This forwards TCP/UDP traffic arriving on host port `5000` into the forwarding namespace, then DNATs it to `114.111.191.26:2616`.

The namespace setup creates:

- a Linux network namespace, default `fwd`
- a veth pair, default `fwd-host` and `fwd-ns`
- host and namespace veth IPs, default `10.200.0.1/30` and `10.200.0.2/30`
- a default route inside the namespace
- IPv4 forwarding via `sysctl`

## What `apply` Does On A New Host

`apply` performs one reconciliation pass and exits. On a fresh host, using the example config, it converges the machine into a working forwarding topology.

Before changing networking state, it checks that these commands are available:

```bash
command -v ip
command -v nft
command -v conntrack
command -v sysctl
```

Then it creates or updates the network namespace and veth link. With the default namespace `fwd`, host veth IP `10.200.0.1/30`, and namespace veth IP `10.200.0.2/30`, the effective commands are:

```bash
ip netns add fwd
ip link add fwd-host type veth peer name fwd-ns
ip link set fwd-ns netns fwd
ip addr replace 10.200.0.1/30 dev fwd-host
ip link set fwd-host up
ip netns exec fwd ip addr replace 10.200.0.2/30 dev fwd-ns
ip netns exec fwd ip link set fwd-ns up
ip netns exec fwd ip link set lo up
ip netns exec fwd ip route replace default via 10.200.0.1
sysctl -w net.ipv4.ip_forward=1
ip netns exec fwd sysctl -w net.ipv4.ip_forward=1
```

The create steps are idempotent. If the namespace or links already exist, `xelay` skips those creation commands and still refreshes addresses, link state, route, and forwarding settings.

Next, it loads or creates the state file, default:

```text
/var/lib/xelay/state.json
```

It attempts to read existing nftables counters from the namespace:

```bash
ip netns exec fwd nft -j list table inet xelay_fwd
```

On a new host this table usually does not exist yet, so the first counter read is treated as empty. It also checks current conntrack flows for each rule:

```bash
ip netns exec fwd conntrack -L -n
```

Finally, it replaces the nftables rules it owns. On the host it deletes old controller tables if present:

```bash
nft delete table ip xelay_hostnat
nft delete table ip xelay_hostfwd
```

Then it applies host-side nftables rules equivalent to:

```nft
table ip xelay_hostnat {
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  oifname "eth0" ip saddr 10.200.0.1/30 masquerade
 }
}

table ip xelay_hostfwd {
 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
  tcp dport 5000 dnat to 10.200.0.2:5000
  udp dport 5000 dnat to 10.200.0.2:5000
 }
}
```

Inside the namespace, it deletes the old forwarding table if present:

```bash
ip netns exec fwd nft delete table inet xelay_fwd
```

Then it applies namespace-side nftables rules equivalent to:

```nft
table inet xelay_fwd {
 counter svc_5000_in_tcp { }
 counter svc_5000_out_tcp { }
 counter svc_5000_in_udp { }
 counter svc_5000_out_udp { }

 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
  ct state new tcp dport 5000 counter name svc_5000_in_tcp dnat to 114.111.191.26:2616
  ct state new udp dport 5000 counter name svc_5000_in_udp dnat to 114.111.191.26:2616
 }

 chain forward { type filter hook forward priority filter; policy drop;
  ct state established,related accept
  ip daddr 114.111.191.26 tcp dport 2616 accept
  ip daddr 114.111.191.26 udp dport 2616 accept
 }

 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  oifname != "fwd-ns" masquerade
  ip daddr 114.111.191.26 tcp sport 2616 counter name svc_5000_out_tcp accept
  ip daddr 114.111.191.26 udp sport 2616 counter name svc_5000_out_udp accept
 }
}
```

After a successful first `apply`, the host should roughly look like this:

```text
host namespace
  eth0                 external host interface
  fwd-host             10.200.0.1/30, up
  nft xelay_hostnat    masquerades namespace egress through eth0
  nft xelay_hostfwd    DNATs host :5000 traffic to 10.200.0.2:5000

fwd network namespace
  lo                   up
  fwd-ns               10.200.0.2/30, up
  default route        via 10.200.0.1
  nft xelay_fwd        DNAT/filter/SNAT/counter rules
```

Traffic relay path for the example rule:

```text
client -> host eth0:5000
  -> host nft prerouting DNAT: 10.200.0.2:5000
  -> veth fwd-host/fwd-ns into namespace fwd
  -> namespace nft prerouting DNAT: 114.111.191.26:2616
  -> namespace forward chain allows the backend flow
  -> namespace postrouting masquerades egress traffic
  -> backend 114.111.191.26:2616
```

Return traffic follows conntrack/NAT state back through the namespace and host to the original client. The named nftables counters are used later by `status`, `run`, and subsequent `apply` calls to maintain quota accounting.

## nftables Behavior

The controller owns nftables tables named with the `xelay_*` prefix.

On each apply/reconcile pass, it recreates its managed tables and installs:

- host-side masquerade rules
- host-side DNAT rules into the forwarding namespace
- namespace-side DNAT rules to backend targets
- namespace-side filter rules
- named nftables counters for inbound and outbound accounting

## Quotas And Limits

Each rule can define:

- inbound byte quota
- outbound byte quota
- maximum TCP connections
- maximum UDP flows
- enabled/disabled state

Quota strings support values such as `500GB`, `1024MB`, `1TB`, or raw byte counts.
Omitting `quota_in` or `quota_out` means that direction is unlimited. Omitting `max_tcp_connections` or `max_udp_flows`, or setting them to `0`, also means unlimited.

An apply-only rule can omit all limit fields:

```json
{
  "name": "svc-5000",
  "listen_port": 5000,
  "protocols": ["tcp", "udp"],
  "target_host": "114.111.191.26",
  "target_port": 2616
}
```

A monitored rule defines at least one quota or connection limit:

```json
{
  "name": "svc-5000",
  "listen_port": 5000,
  "protocols": ["tcp", "udp"],
  "target_host": "114.111.191.26",
  "target_port": 2616,
  "quota_in": "500GB",
  "quota_out": "500GB",
  "max_tcp_connections": 2000,
  "max_udp_flows": 4000
}
```

Runtime rule states include:

- `enabled`
- `disabled-by-config`
- `quota-blocked`
- `tcp-limit-blocked`
- `udp-limit-blocked`

When TCP is blocked due to quota or connection limits, new TCP flows are blocked while established flows can continue draining. UDP limit blocking disables forwarding more directly.

## Reconciliation Loop

The core loop performs these steps:

1. Check required Linux commands.
2. Ensure namespace networking exists.
3. Read current nftables counters.
4. Merge counter deltas into persisted state.
5. Count live conntrack flows.
6. Decide runtime state for each rule.
7. Re-apply nftables rules.
8. Save state to disk.

## Persisted State

The state file defaults to:

```text
/var/lib/xelay/state.json
```

It stores cumulative byte totals, nftables counter baselines, and each rule's current runtime state. This allows quota accounting to survive controller restarts.

## Main Code Areas

- `src/main.rs`: CLI entry point.
- `src/cli.rs`: command definitions and human-readable output.
- `src/config.rs`: JSON config loading, defaults, quota parsing, validation.
- `src/namespace.rs`: Linux network namespace and veth setup.
- `src/nft.rs`: nftables rule rendering, apply logic, counter parsing.
- `src/conntrack.rs`: live TCP/UDP flow counting.
- `src/state.rs`: persisted controller state.
- `src/reconcile.rs`: controller workflow and enforcement decisions.

## Test Status

The Rust test suite currently passes:

```text
47 passed; 0 failed
```
