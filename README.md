# Xelay

`nftable-backend/` contains the completed v1 nftables implementation.

`tc-ebpf-backend/` contains the v2 TC eBPF implementation. The v2 controller is
Rust/Aya based and keeps the first milestone focused on IPv4 TCP/UDP forwarding,
BPF map counters, attach/detach, status, and cleanup.

