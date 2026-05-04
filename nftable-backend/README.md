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
xelay --config config.json clean
```

- no subcommand: loads config from `./config.json` or `/etc/config/xelay/config.json`, then chooses `apply` or `run` automatically.
- `apply`: performs one reconciliation pass, then exits.
- `run`: continuously reconciles at the configured polling interval.
- `status`: prints rule state, byte counters, quotas, and flow counts.
- `check`: verifies required external Linux tools are available.
- `clean`: removes xelay-owned nftables tables and the configured network namespace.

Automatic mode chooses `run` when any enabled rule defines `quota_in`, `quota_out`, `max_tcp_connections`, or `max_udp_flows`. If no enabled rule has limits, it performs `apply` once.

## Runtime Dependencies

`xelay` shells out to standard Linux networking tools:

- `ip`
- `nft`
- `iptables` when Docker's `DOCKER-USER` chain exists
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
  iifname "eth0" tcp dport 5000 dnat to 10.200.0.2:5000
  iifname "eth0" udp dport 5000 dnat to 10.200.0.2:5000
 }
}
```

If Docker is installed, Docker may also create an `ip filter` `FORWARD` chain with
`policy drop`. When the Docker `DOCKER-USER` chain exists, `xelay` installs matching
accept rules there with `iptables -w` so forwarded traffic can reach the namespace
without editing Docker-managed chains. On each apply/reconcile pass, xelay first
removes xelay-owned `DOCKER-USER` rules and then installs rules for the current
config, so stale entries from older configs are not left behind.

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
  ct state new tcp dport 5000 counter name svc_5000_in_tcp dnat ip to 114.111.191.26:2616
  ct state new udp dport 5000 counter name svc_5000_in_udp dnat ip to 114.111.191.26:2616
 }

 chain forward { type filter hook forward priority filter; policy drop;
  ct state established,related accept
  ip daddr 114.111.191.26 tcp dport 2616 accept
  ip daddr 114.111.191.26 udp dport 2616 accept
 }

 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  ip daddr 114.111.191.26 tcp dport 2616 counter name svc_5000_out_tcp masquerade
  ip daddr 114.111.191.26 udp dport 2616 counter name svc_5000_out_udp masquerade
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
- pruned and refreshed Docker `DOCKER-USER` accept rules when Docker's forwarding hook exists
- namespace-side DNAT rules to backend targets
- namespace-side filter rules
- named nftables counters for inbound and outbound accounting

## Cleanup

Use `clean` to tear down the forwarding infrastructure created by `apply` or `run`:

```bash
xelay --config config.json clean
```

This removes only xelay-owned networking state:

- host nftables tables `xelay_hostnat` and `xelay_hostfwd`
- xelay accept rules from Docker's `DOCKER-USER` chain when it exists
- namespace nftables table `xelay_fwd`
- the configured network namespace and any leftover host-side veth link

The configured state file is preserved so quota and runtime history remain available
for later inspection or reuse.

## systemd Service

Use the provided unit file to recreate namespace, veth, nftables, Docker hook, and
runtime routes after reboot.

Build and install the binary:

```bash
cargo build --release
sudo install -m 0755 target/release/xelay /usr/local/bin/xelay
```

Install and edit the config:

```bash
sudo install -d /etc/config/xelay
sudo install -m 0644 config.example.json /etc/config/xelay/config.json
sudo nano /etc/config/xelay/config.json
```

At minimum, set:

- `host_interface` to the host's external interface, such as `eth0` or `ens3`
- each rule's `listen_port`
- each rule's `protocols`
- each rule's `target_host`
- each rule's `target_port`

Install and enable the service:

```bash
sudo install -m 0644 contrib/systemd/xelay.service /etc/systemd/system/xelay.service
sudo systemctl daemon-reload
sudo systemctl enable --now xelay
```

Check service status and logs:

```bash
sudo systemctl status xelay
sudo journalctl -u xelay -f
```

The service runs:

```bash
/usr/local/bin/xelay --config /etc/config/xelay/config.json run
```

It is ordered after `network-online.target` and `docker.service`. If Docker is
installed, this gives Docker a chance to create `DOCKER-USER` before xelay installs
its accept rules. Stopping the service does not clean the dataplane; use
`xelay --config /etc/config/xelay/config.json clean` when you intentionally want to
remove xelay networking state.

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
