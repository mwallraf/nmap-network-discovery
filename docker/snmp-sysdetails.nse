-- nmap NSE script: /usr/share/nmap/scripts/snmp-sysdetails.nse
-- nmap -sU -p 22,23,161 -PE -PS22,23 -T4 -n --script snmp-brute,snmp-sysdescr,snmp-sysdetails,snmp-info  --script-args snmp-brute.communitiesdb=/tmp/communities,snmp.timeout=2000 25.0.96.1 25.0.32.1 -vvv -d -oX /tmp/test.xml

local datetime = require "datetime"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local string = require "string"
local stdnse = require "stdnse"

description = [[
Get SysObjID from a device using SNMP.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-sysdetails <target>
-- nmap -sU -p 161 --script snmp-brute,snmp-sysdetails --script-args snmp-brute.communitiesdb=comms.txt <target>
--
-- @output
-- | snmp-sysdetails:
-- |   sysObjectId: 1.3.6.1.4.1.9.1.1745
-- |   sysContact:
-- |   serial: FCQ2342343243
-- |   sysName: TTN-DCN3850.dcn.as47377.net
-- |_  sysLocation:

author = "Maarten Wallraf"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}


portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

---
-- Sends SNMP packets to host and reads responses
---
action = function(host, port)

  -- checks for arguments: snmp.timeout,snmp.version
  local snmp_timeout = stdnse.get_script_args({"snmp.timeout", "timeout"}) or 5000
  local snmp_version = stdnse.get_script_args({"snmp.version", "version"}) or "v2c"
  local snmp_options = {timeout=snmp_timeout, version=snmp_version}

  local oid_sysobjid = "1.3.6.1.2.1.1.2.0" -- (SNMPv2-MIB::sysObjectId.0)
  local oid_syscontact = "1.3.6.1.2.1.1.4.0" -- (SNMPv2-MIB::sysContact.0)
  local oid_sysname = "1.3.6.1.2.1.1.5.0" -- (SNMPv2-MIB::sysName.0)
  local oid_syslocation = "1.3.6.1.2.1.1.6.0" -- (SNMPv2-MIB::sysLocation.0)
  local oid_chassis_serial = "1.3.6.1.2.1.47.1.1.1.1.11.1" 

  local snmpHelper = snmp.Helper:new(host, port, nil, snmp_options)
  snmpHelper:connect()

  -- send SNMP GET requests
  local status1, response_sysobjid = snmpHelper:get({}, oid_sysobjid)
  local status2, response_syscontact = snmpHelper:get({}, oid_syscontact)
  local status3, response_sysname = snmpHelper:get({}, oid_sysname)
  local status4, response_syslocation = snmpHelper:get({}, oid_syslocation)
  local status5, response_serial = snmpHelper:get({}, oid_chassis_serial)

  if not (status1 or status2 or status3 or status4 or status5) then
    return
  end

  -- since we got something back, the port is definitely open
  nmap.set_port_state(host, port, "open")

  local output = stdnse.output_table()

  if status1 then
    output.sysObjectId = snmp.oid2str(response_sysobjid[1][1])
  else
    output.sysObjectId = "unknown"
  end

  if status2 then
    output.sysContact = response_syscontact[1][1]
  else
  	output.sysContact = "unknown"
  end

  if status3 then
    output.sysName = response_sysname[1][1]
  else
  	output.sysName = "unknown"
  end

  if status4 then
    output.sysLocation = response_syslocation[1][1]
  else
  	output.sysLocation = "unknown"
  end

  if status5 then
    output.serial = response_serial[1][1]
  else
  	output.serial = "unknown"
  end

  return output
end
