# Changelog

## 1.0.1

- Rename the MSS clamp chain to `tcp_mss` so nftables versions that reserve `mss` can parse the ruleset.
- Run real namespace and published-source installation checks on Ubuntu 22.04 and 24.04.
- Compare installed and checked-out versions dynamically in CI.

## 1.0.0

- Initial Persian terminal manager for multiple independent GRE-over-FOU links.
- Per-link services, port forwarding, peer setup links and configuration validation.
- Diagnostics, interface traffic counters, optional health timers and backup/restore.
- GitHub installer with checksum verification and selectable Git ref.
- Persian and English documentation, unit tests and an optional namespace integration test.
- No encryption or automatic load balancing in this version.
