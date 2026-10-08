# nmap-network-discovery

[![Docker image](https://github.com/mwallraf/nmap-network-discovery/actions/workflows/docker-image.yml/badge.svg)](https://github.com/mwallraf/nmap-network-discovery/actions/workflows/docker-image.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Find network devices and learn what they are, in one nmap run.**

A ready-to-run Docker image with nmap and masscan, plus two custom nmap scripts
that ask every device it finds over SNMP for its name, model, serial number,
software version, interfaces and customer services.

- **Inventory in one pass:** hostname, model, serial and software for routers,
  switches and other SNMP devices (generic ENTITY-MIB, with Ciena support).
- **Interfaces and services:** every interface with its IPv4 addresses and the
  service IDs (for example `VT123456`) found in its description.
- **Fast on large networks:** bulk SNMP requests and no time wasted on hosts
  that do not answer SNMP.
- **Nothing to install** except Docker. Results in nmap's normal, XML and grep
  formats.

## Quick start

```bash
git clone https://github.com/mwallraf/nmap-network-discovery.git
cd nmap-network-discovery

# SNMP community strings to try, one per line
printf 'public\nprivate\n' > input/communities.txt

docker compose run --rm network-discovery -n -Pn -sU -p 161 \
  --script snmp-brute,snmp-sysdetails,snmp-ifalias-service \
  --script-args snmp-brute.communitiesdb=/app/input/communities.txt \
  -oX /app/output/scan.xml \
  192.168.1.0/24
```

The image is pulled from GitHub Container Registry on first use. Results are
printed and saved to `output/scan.xml`.

```
161/udp open  snmp
| snmp-brute:
|_  private - Valid credentials
| snmp-sysdetails:
|   sysDescr: ONEOS16-MONO_FT-V5.2R2E7_HA8
|   sysObjectId: 1.3.6.1.4.1.13191.1.1.140
|   sysUpTime: 57d21h06m33.41s (500079341 timeticks)
|   sysName: lab-router-01
|   physSerial: T1703006230033175
|   physModel: LBB_140
|   ...
| snmp-ifalias-service:
|   GigabitEthernet0/0/2.100:
|     ifIndex: 12
|     ifAlias: VT123456 customer-a
|     services:
|       VT123456
|     addresses:
|_      10.20.30.1/30
```

---

## Contents

- [How it works](#how-it-works)
- [The NSE scripts](#the-nse-scripts)
- [Usage examples](#usage-examples)
- [Configuration](#configuration)
- [Image tags and building](#image-tags-and-building)
- [Using the scripts without Docker](#using-the-scripts-without-docker)
- [Notes](#notes)

## How it works

1. nmap finds hosts and checks UDP port 161 (SNMP).
2. nmap's built-in `snmp-brute` tries the community strings from your list and
   remembers the one that works.
3. `snmp-sysdetails` and `snmp-ifalias-service` use that community to read the
   device details.

The two custom scripts only poll a device when a working community is known
(found by `snmp-brute` or given with `creds.snmp`) or when the device already
answered SNMP. Silent hosts are skipped immediately instead of costing a full
SNMP timeout each, which matters a lot when scanning large ranges.

## The NSE scripts

### snmp-sysdetails

System and hardware details of the device, read with two SNMP requests.

| Field | Source |
|---|---|
| `sysDescr`, `sysObjectId`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation` | SNMPv2-MIB system group |
| `physSerial`, `physSoftware`, `physModel`, `physDescription`, `physName` | ENTITY-MIB, first physical entity |

For Ciena devices (WWP) the serial, software, description and name are read
from the Ciena MIB instead. Fields the device does not have are left out.

### snmp-ifalias-service

Every interface that has a service ID in its alias (`ifAlias`) or an IPv4
address, keyed by interface name:

| Field | Content |
|---|---|
| `ifIndex` | SNMP interface index |
| `ifAlias` | Interface description, if set |
| `services` | Service IDs matched in the alias (default pattern `VT%d+`) |
| `addresses` | IPv4 addresses in CIDR notation, including secondaries |

The interface and address tables are walked together with GETBULK requests
(SNMPv2c): in testing, a router with 300 interfaces took 20 requests instead
of more than 1,300 one row at a time. SNMPv1 devices fall back to GETNEXT.

### Script arguments

Pass them with `--script-args`, separated by commas.

| Argument | Default | Description |
|---|---|---|
| `snmp-brute.communitiesdb` | nmap's built-in list | File with community strings to try |
| `creds.snmp` | | Use this community directly, without `snmp-brute` |
| `snmp.version` | `v2c` | `v1` or `v2c` |
| `snmp.timeout` | `5000` | Timeout per SNMP request, in milliseconds |
| `snmp-ifalias-service.pattern` | `VT%d+` | [Lua pattern](https://www.lua.org/manual/5.4/manual.html#6.4.1) for service IDs in the interface alias |
| `snmp-ifalias-service.maxrepetitions` | `25` | Rows per GETBULK request; lower it if a device drops large replies |

## Usage examples

All examples use Docker Compose from the repository folder. Everything after
`network-discovery` is passed to nmap. Files in `input/` are available as
`/app/input`, and results written to `/app/output` end up in `output/`.

**Single device, community known:**

```bash
docker compose run --rm network-discovery -n -Pn -sU -p 161 \
  --script snmp-sysdetails,snmp-ifalias-service \
  --script-args creds.snmp=mycommunity \
  10.0.0.1
```

**Discover SSH/Telnet devices in a list of subnets and poll them over SNMP:**

```bash
docker compose run --rm network-discovery -n -PS22,23 -sS -sU \
  -p T:22,23,179,U:161 -T4 \
  --script snmp-brute,snmp-sysdetails,snmp-ifalias-service \
  --script-args snmp-brute.communitiesdb=/app/input/communities.txt,snmp.timeout=3000 \
  -iL /app/input/targets.txt \
  -oX /app/output/discovery.xml -oG /app/output/discovery.grep
```

**Only SNMPv1, other service ID format:**

```bash
docker compose run --rm network-discovery -n -Pn -sU -p 161 \
  --script snmp-sysdetails,snmp-ifalias-service \
  --script-args 'creds.snmp=mycommunity,snmp.version=v1,snmp-ifalias-service.pattern=SRV%-%d+' \
  10.0.0.1
```

**Fast port sweep with masscan, or a shell in the container:**

```bash
docker compose run --rm --entrypoint masscan network-discovery -p22,23 192.168.100.0/24
docker compose run --rm --entrypoint bash network-discovery
```

<details>
<summary><b>Without Docker Compose (plain <code>docker run</code>)</b></summary>

```bash
docker run --rm \
  -v "$(pwd)/input:/app/input:ro" \
  -v "$(pwd)/output:/app/output" \
  ghcr.io/mwallraf/nmap-network-discovery:latest \
  -n -Pn -sU -p 161 \
  --script snmp-brute,snmp-sysdetails,snmp-ifalias-service \
  --script-args snmp-brute.communitiesdb=/app/input/communities.txt \
  -oX /app/output/scan.xml \
  192.168.1.0/24
```

</details>

<details>
<summary><b>Troubleshooting</b></summary>

- **No output from the custom scripts:** no working community was found, or the
  device stopped answering during the walk. Add `-d` to see why a host was
  skipped.
- **No interface output for a large device:** lower
  `snmp-ifalias-service.maxrepetitions` (for example to `10`) and raise
  `snmp.timeout`.
- **Community strings with commas or spaces:** quote them inside the script
  arguments, for example `--script-args 'creds.snmp="my,community"'`.

</details>

## Configuration

Docker Compose reads optional settings from a `.env` file next to
`docker-compose.yml`. Copy [`.env.example`](.env.example) to start:

| Variable | Default | Description |
|---|---|---|
| `NMAP_DISCOVERY_IMAGE` | `ghcr.io/mwallraf/nmap-network-discovery` | Image to run or build |
| `NMAP_DISCOVERY_TAG` | `latest` | Image tag, see below |
| `GROUPID` | `20001` | Group ID of the `app` group in the image (build only) |
| `http_proxy`, `https_proxy` | | Proxy for package downloads (build only) |

To scan a local LAN without Docker's NAT (needed for ARP host discovery),
enable `network_mode: host` in `docker-compose.yml`. This works on Linux only.

## Image tags and building

Images are built by GitHub Actions and published to
[GitHub Container Registry](https://github.com/mwallraf/nmap-network-discovery/pkgs/container/nmap-network-discovery):

| Tag | Built from |
|---|---|
| `latest`, `1.2`, `1.2.0` | Release tags (`v1.2.0`) |
| `main` | Latest commit on `main` |
| `sha-<commit>` | A specific commit |

To build the image yourself, for example after changing a script:

```bash
docker compose build
```

## Using the scripts without Docker

The scripts work with any recent nmap installation:

```bash
sudo cp docker/snmp-*.nse "$(dirname "$(dirname "$(which nmap)")")/share/nmap/scripts/"
sudo nmap --script-updatedb
sudo nmap -sU -p 161 --script snmp-brute,snmp-sysdetails,snmp-ifalias-service <target>
```

## Notes

- The image is based on `kalilinux/kali-rolling` and runs nmap as root, which
  UDP and SYN scans need. On Linux, files in `output/` are therefore owned by
  root.
- The contents of `input/` and `output/` are ignored by git, so community
  lists and scan results are not committed by accident.
- Only scan networks you are authorized to scan.

## License

[MIT](LICENSE)
