# English guide

[Home](../README.md) · [فارسی](README.fa.md)

## Install and update

Run on both directly addressed IPv4 Linux servers:

```bash
curl -fL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/admin6501/gre-fou-manager/main/install.sh -o install-gre-fou.sh
sudo bash install-gre-fou.sh
sudo gre-fou
```

The installer downloads the manager and verifies the SHA-256 manifest. The downloaded manifest is an integrity check, not an independent signature. Use `--ref` with an existing branch, tag or commit SHA to select code; a commit SHA gives reproducible source selection. Refs containing `/` are not accepted. Use `--no-deps` if all required tools are already installed.

Re-running installation updates the manager and systemd unit templates while retaining tunnel configuration. It does not rebuild running tunnel interfaces. Restart each tunnel to apply changed networking logic.

Requirements: root, active systemd, directly configured IPv4 addresses, Python 3, iproute2, nftables, kmod, ping, and kernel support for `ip_gre` and `fou`. The installer supports apt-get and dnf. Containers and restricted VPS products may lack NET_ADMIN or kernel support.

## Terminal menu

The runtime menu and prompts are Persian. Select numbers and press Enter; accepting defaults also uses Enter. Noninteractive commands below are available for day-to-day operations.

| Main menu | Function |
|---|---|
| 1. ساخت تونل | Create tunnel |
| 2. نصب از لینک سمت مقابل | Import peer setup link |
| 3. وضعیت همه تونل‌ها | List status |
| 4. مدیریت یک تونل | Manage one named tunnel |
| 5. بکاپ | Back up configuration |
| 6. بازیابی بکاپ بدون جایگزینی | Restore without overwriting |
| 0. خروج | Exit |

The management submenu offers status, start, stop, restart, edit, add/remove forwarding, peer link, diagnostics, logs, delete, and health-monitor enable/disable.

## Create a pair

1. On the Iran server, choose menu option 1 and use a name such as `ir1fr1`.
2. Enter that server's configured public IPv4 as **local** and the foreign server's IPv4 as **remote**. NAT endpoints are not supported.
3. Select local/remote UDP receive ports, two usable RFC1918 addresses in one /30, a nonzero GRE key and an MTU (default 1380).
4. Copy the printed `grefou://1...` link to the foreign server and select menu option 2.
5. The link reverses endpoint IPs, UDP ports and inner addresses. It retains the key and MTU and drops the originating server's forwarding list.
6. Names can differ on the two servers. All wire parameters must agree.

Every local tunnel needs a distinct FOU port and /30 subnet. If the foreign server already uses the proposed port or subnet, edit the originating side and generate a fresh link. Setup links are neither encrypted nor digitally signed; import only links you trust.

The manager does not use SSH to provision the peer. Install it on both machines before importing a link.

For noninteractive initial creation, copy [the example JSON](../examples/ir1fr1.json), replace the documentation IPv4 addresses with the actual server addresses, and run:

```bash
sudo gre-fou create ir1fr1.json
sudo gre-fou link ir1fr1
```

`create` starts the tunnel and enables it for boot. Peer import is also exposed as `gre-fou import-link`; use `gre-fou import-link --help` for arguments.

## Forwarding

Forwarding goes from the local public IPv4 to the peer's tunnel IPv4. The destination service must listen on the peer's inner address or `0.0.0.0`, not only localhost or the peer's public IPv4.

```bash
sudo gre-fou forward-add ir1fr1 both 2082,2053,3000-3010
sudo gre-fou forward-add ir1fr1 tcp 443 --target 8443
sudo gre-fou status ir1fr1
sudo gre-fou forward-delete ir1fr1 1
```

Each TCP/UDP entry has its own index in `status`. A different target port is supported only when selecting one input port. Source NAT makes the peer service see the local inner tunnel IP; original client IP preservation is not implemented.

Forwarding only handles incoming packets via PREROUTING. Test the public forwarding endpoint from a third machine. Connections originating on the local server to its own public address are not covered by an OUTPUT DNAT rule.

## Multiple servers

Create one independent link for every desired server pair. Both sides are symmetric, even though this guide starts on Iran.

| Pair | Iran FOU port | Foreign FOU port | Iran inner IPv4 | Foreign inner IPv4 | Public forwarding |
|---|---:|---:|---|---|---|
| `ir1fr1` | 5555 | 6665 | 10.240.0.1 | 10.240.0.2 | TCP/UDP 2082 |
| `ir1tr1` | 5556 | 6666 | 10.240.0.5 | 10.240.0.6 | TCP/UDP 2083 |

The same public IP/port/protocol tuple cannot target two peers simultaneously. For many Iran servers to one foreign server, use distinct ports/subnets for every link on the shared foreign host. For many-to-many arrangements, repeat for each selected pair. Automatic load balancing and peer failover are not implemented.

## Firewall

Allow each local FOU UDP port from the peer's public IPv4. Permit incoming user ports and their forwarded connections on Iran. Permit destination services in INPUT from the tunnel interface and the Iran inner IP on the foreign host. The provider firewall must permit the outer UDP flow as well.

For `ir1fr1`, the interface is `gfir1fr1`, the nftables table is `ip gfm_ir1fr1`, and the service is `gre-fou@ir1fr1.service`. The manager owns separate tables and never flushes the global ruleset. Its ACCEPT verdicts do not override later DROP verdicts from UFW, firewalld or other base chains.

Adding forwarding enables the global `net.ipv4.ip_forward` setting. Removing the tunnel does not turn it off globally because other services may use it.

## Status, health checks and logs

```bash
sudo gre-fou status
sudo gre-fou diagnose ir1fr1
sudo gre-fou logs ir1fr1
sudo gre-fou monitor ir1fr1 on
sudo gre-fou monitor ir1fr1 off
sudo systemctl status gre-fou-health@ir1fr1.timer --no-pager
```

The monitor is off by default. When enabled, it checks the peer inner IP approximately once a minute and restarts the local tunnel after three failed checks. If ICMP is blocked, it can restart an otherwise functioning tunnel. A locally active systemd service does not prove peer connectivity.

RX/TX values are interface counters since interface creation, and reset on recreation or reboot. No persistent traffic quota is implemented.

## Lifecycle and backup

```bash
sudo gre-fou stop ir1fr1
sudo gre-fou start ir1fr1
sudo gre-fou restart ir1fr1
sudo gre-fou backup /root/gre-fou-backup.json
sudo gre-fou restore /root/gre-fou-backup.json
```

`start` enables boot startup; `stop` disables it. Edit through the menu. Endpoint, port, key or subnet changes require matching peer updates. If a changed local service fails to start, the manager attempts to restore its previous configuration and reports rollback failures.

Backups contain configurations, not live connections or cumulative counters. They refuse an existing destination filename. Restore refuses existing tunnel names and validates the entire batch before writing. Restored tunnels are not started automatically. Restoring to different servers requires adjusting endpoint IPs.

Menu deletion asks you to re-enter the tunnel name. Noninteractive deletion does not ask:

```bash
sudo gre-fou remove ir1fr1
```

This removes the named tunnel, its local configuration and health timer. It does not delete the peer's configuration.

## Security and scope

This version has no encryption or authenticated handshake. GRE keys identify tunnels; they are not passwords. Peer IP restrictions do not provide cryptographic authentication. WireGuard was discussed as a possible layer but is not implemented in this release.

With an IPv4 outer header, UDP and keyed GRE, added encapsulation overhead is 36 bytes per original IP packet, excluding Ethernet, retransmissions and control traffic. Smaller packets have a larger percentage overhead.

IPv6 outer endpoints, NAT traversal, automatic load balancing, automatic cross-peer failover and global installer removal are not implemented. The initial development container did not permit real GRE/FOU network operations. The Ubuntu 24.04 GitHub Actions namespace check passed on 2026-10-02 for ping, TCP/UDP forwarding, SNAT and cleanup. CI checks published-source installation by commit SHA on push events. See [verification](../README.md#verification) for unit and optional namespace testing.
