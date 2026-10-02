# GRE over FOU Manager

[راهنمای فارسی](docs/README.fa.md) · [English guide](docs/README.en.md)

A Persian terminal manager for independent IPv4 GRE-over-FOU tunnels on Linux. Connect many Iran servers to many foreign servers, or several foreign servers to one Iran server, by creating a separate tunnel for each pair.

مدیریت تانل GRE داخل UDP، با منوی فارسی، فوروارد TCP و UDP و اتصال چند سرور از طریق تونل‌های مستقل.

## Install / نصب

Run on **both servers**. These commands download the installer before executing it; they do not require editing files in a terminal.

روی **هر دو سرور** اجرا کنید:

```bash
curl -fL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/admin6501/gre-fou-manager/main/install.sh -o install-gre-fou.sh
sudo bash install-gre-fou.sh
sudo gre-fou
```

The installer downloads the manager and verifies its SHA-256 checksum. For a reproducible installation, pass an existing commit SHA with `--ref`. Downloaded checksums are an integrity check, not an independent release signature.

## Features / امکانات

- Independent GRE key, UDP ports, /30 inner subnet and systemd service for each tunnel.
- Create, edit, start, stop, restart and delete tunnels through a numbered Persian menu.
- Peer setup links swap endpoint addresses and ports automatically.
- TCP/UDP forwarding, port ranges and single-port translation.
- Configuration checks for duplicate ports, subnets, GRE endpoint/key tuples and forwarding rules.
- Interface RX/TX counters, connectivity diagnostics and service logs.
- Configuration backup and restore without overwriting existing tunnels.
- Optional one-minute ICMP health checks: restart the local tunnel after three failed checks.
- Per-tunnel nftables tables; no global firewall flush.

## First connection / اتصال اول

1. Install the manager on both servers.
2. On Iran, choose **1. ساخت تونل**. Enter that server's IPv4 and the foreign server's IPv4.
3. Copy the printed setup link. On the foreign server, choose **2. نصب از لینک سمت مقابل**.
4. On Iran, choose **4. مدیریت یک تونل → 6. افزودن فوروارد**.
5. Ensure the target service listens on `0.0.0.0` or the foreign tunnel's inner IP. Test from a third device.

Full instructions and firewall requirements are in the guides above. Run `gre-fou guide` to read the Persian guide locally.

## Requirements and limits

Linux, an active systemd host, root/NET_ADMIN, Python 3, iproute2, nftables, kmod and ping. Dependency installation supports apt-get and dnf. Intended distributions: Ubuntu 22.04/24.04, Debian 12/13 and AlmaLinux/Rocky 9; actual GRE/FOU support depends on the host kernel and provider permissions. A minimal OpenVZ/container guest is not assumed to support this.

- Direct IPv4 endpoints only; NAT and IPv6 endpoint support are not implemented.
- **No encryption or authenticated handshake. A GRE key is an identifier, not a password. WireGuard has not been added.**
- Independent links and forwarding rules; no automatic load balancing or failover between foreign servers.
- Existing UFW, firewalld, nftables and provider DROP rules may still block traffic. This manager does not disable them.
- Forwarding applies to packets received from other devices, not connections originating locally to the server's public address.
- Source NAT makes the destination see the Iran tunnel's inner IP rather than the original client IP.
- RX/TX counters reset when the interface is recreated. Backups contain configuration, not cumulative traffic or live conntrack sessions.

## Verification

```bash
bash -n gre-fou-manager.sh
bash -n install.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

An optional root-only namespace test creates two tunnel endpoints and a third client, then checks ICMP, TCP forwarding, UDP forwarding and cleanup:

```bash
sudo bash tests/integration.sh
```

The initial development environment denied NET_ADMIN, so real kernel/two-server traffic was not tested there. Unit tests use mocked network commands. The namespace test requires a suitable Linux host; it is not a throughput or Iran-to-foreign network benchmark.
