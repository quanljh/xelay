# Rust v1 Plan for Namespace-Isolated Linux Port Forwarder

## Summary
Build a single Rust binary, `xelay`, that manages one dedicated Linux network namespace (`fwd`) and uses `ip`, `nft`, and `conntrack` to provide IPv4-only TCP/UDP port forwarding with kernel-path NAT, per-rule traffic quotas, global per-rule connection limits, and operator-facing status output.

The binary supports both one-shot reconciliation and a long-running daemon loop. v1 persists quota/accounting state on disk so limits survive controller restarts and host reboot, while the dataplane remains nftables + conntrack in the kernel.

## Key Changes
- Create a new Rust CLI application with modules for config loading, namespace lifecycle, nftables rule rendering/apply, conntrack inspection, reconcile loop, persisted state, and CLI/status formatting.
- Keep execution model explicit: a privileged controller shelling out to `ip`, `nft`, and `conntrack`.
- Use human-readable `quota_in` and `quota_out` fields, accepting suffixes such as `MB`, `GB`, `TB`, plus raw bytes.
- Provide `apply`, `run`, `status`, and `check` subcommands.
- Make namespace setup idempotent and keep all nftables ownership under controller-specific tables.
- Persist byte totals, counter baselines, and disable reasons on disk.

## Test Plan
- Validate JSON parsing, including quota strings like `500GB`, `1024MB`, and invalid suffixes.
- Verify idempotent namespace reconciliation and nftables rendering for both TCP and UDP.
- Verify quota enforcement, connection-limit transitions, and persisted accounting across controller restart.
- Verify human-readable status output and dependency checks.

## Assumptions
- v1 is IPv4-only.
- The service runs as root on Linux with `iproute2`, `nftables`, and `conntrack-tools` installed.
- Only one controller instance manages a given namespace and nftables ruleset.
