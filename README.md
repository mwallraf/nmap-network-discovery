# nmap-network-discovery

Kali-based Docker image with nmap and masscan with a custom NSE script for additional SNMP polling.

## Install

Either build the image locally or pull from Docker hub.

```
docker pull mwallraf/nmap-network-discovery:1.0
```

or

```
docker-compose build
```

or

```
cd Docker && docker build . --tag mwallraf/nmap-network-discovery:1.0
```

# NSE SCRIPT: snmp-sysdetails

NMAP NSE script to poll addtional sysinfo and physical OIDs using SNMP. Use in combination with `snmp-brute` or set the snmp creds manually (see nmap.org).

**example:**

    --script snmp-brute,snmp-sysdetails --script-args snmp-brute.communitiesdb=/tmp/communities.txt,snmp.timeout=3000

# Docker Usage

By default the entrypoint is `nmap` so you can directly run the image providing the nmap parameters. If you want to connect to the image or want to use `masscan` instead then change the entrypoint.

If you also want to do SNMP discovery then it's best to map a file with valid community strings.

**Examples:**

Network discovery based on telnet + SSH ports. Get additional port info about telnet, ssh, bgp and try to poll some SNMP system details. The output will be saved to XML and GREP format.

    docker run -it --rm -v $(pwd)/communities:/tmp/communities mwallraf/nmap-network-discovery:1.0 -n -PS22,23 -sU -sS -pT:22,23,179,U:161 -T5 --script snmp-brute,snmp-sysdetails,snmp-info --script-args snmp-brute.communitiesdb=/tmp/communities.txt,snmp.timeout=3000 192.168.1.0/24 -oX /tmp/nmap-out.xml -oG /tmp/nmap-out.grep

Connect to the docker shell.

    docker run -it --rm --entrypoint=bash --rm mwallraf/nmap-network-discovery:1.0

Run masscan discovery instead of nmap.

    docker run -it --rm --entrypoint=masscan mwallraf/nmap-network-discovery:1.0 -p22,23 192.168.100.0/24
