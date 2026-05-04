# Xelay TC eBPF Backend

This is the v2 backend for Xelay. It replaces the nftables dataplane with TC
eBPF programs loaded by a Rust/Aya controller.

The first milestone is an IPv4 TCP/UDP forwarding MVP:

- attach a TC ingress classifier to `host_interface`
- populate BPF rule maps from the existing Xelay config shape
- keep per-rule/protocol/direction byte counters in BPF maps
- provide `apply`, `run`, `status`, `check`, and `clean`
- keep quota and connection-limit fields parseable but not enforced yet

The eBPF crate under `ebpf/` targets `bpfel-unknown-none` and is intentionally
not a workspace member for normal host builds.

## Build

Build the userspace controller:

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

Override the object path with `--bpf-object` when needed.
