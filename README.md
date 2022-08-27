# nmap-network-discovery

Kali-based Docker image with nmap and masscan with some shell scipts used for basic network discovery.

The discovery script will first use masscan to detect network devices based on telnet and SSH ports. Afterwards nmap will run on the discovered hosts and SNMP will be used to get some basic host details.

# Examples

docker run -it --rm -v /Users/mwallraf/Downloads/communities:/tmp/communities nmap-network-discovery:1.0 -sU -p 22,23,161 -PE -PS22,23 -T4 -n --script snmp-brute,snmp-sysdescr,snmp-sysdetails,snmp-info --script-args snmp-brute.communitiesdb=/tmp/communities,snmp.timeout=2000 192.168.100.1 -vvv -d -oX /tmp/test.xml -oG /tmp/test.grep

docker run -it --entrypoint=bash --rm -v /Users/mwallraf/Downloads/communities:/tmp/communities nmap-network-discovery:1.0

docker run -it --entrypoint=masscan nmap-network-discovery:1.0 -p22,23 192.168.100.0/2
