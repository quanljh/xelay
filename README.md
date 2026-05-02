# Xelay Tool Summary

`xelay` is a Rust CLI for namespace-isolated Linux TCP/UDP port forwarding.

It is designed to run as a privileged controller on Linux. It reads a JSON config, creates or updates a dedicated network namespace, installs nftables NAT/filter rules, tracks traffic counters, enforces quotas and connection limits, and reports operator status.

## Commands

```bash
xelay --config config.json apply
xelay --config config.json run
xelay --config config.json status
xelay --config config.json check
```

- `apply`: performs one reconciliation pass, then exits.
- `run`: continuously reconciles at the configured polling interval.
- `status`: prints rule state, byte counters, quotas, and flow counts.
- `check`: verifies required external Linux tools are available.

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
29 passed; 0 failed
```
