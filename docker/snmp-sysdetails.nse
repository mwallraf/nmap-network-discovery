-- nmap NSE script: /usr/share/nmap/scripts/snmp-sysdetails.nse
-- nmap -sU -p 22,23,161 -PE -PS22,23 -T4 -n --script snmp-brute,snmp-sysdetails,snmp-info  --script-args snmp-brute.communitiesdb=/tmp/communities,snmp.timeout=2000 25.0.96.1 25.0.32.1 -vvv -d -oX /tmp/test.xml

local datetime = require "datetime"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local string = require "string"
local stdnse = require "stdnse"

description = [[
Get additional information from a device using SNMP. System information and platform information is gathered. Use in combination with "snmp-brute"
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-sysdetails <target>
-- nmap -sU -p 161 --script snmp-brute,snmp-sysdetails --script-args snmp-brute.communitiesdb=comms.txt <target>
--
-- @output
-- | snmp-sysdetails:
-- |   sysDescr: ONEOS16-MONO_FT-V5.2R2E7_HA8
-- |   sysObjectId: 1.3.6.1.4.1.13191.1.1.140
-- |   sysUpTime: 57d21h06m33.41s (500079341 timeticks)
-- |   sysContact: test
-- |   sysName: dops-lab-02.as47377.net
-- |   sysLocation:
-- |   physSerial: T1703006230033175
-- |   physSoftware:
-- |   physModel: LBB_140
-- |   physDescription: LBB_140
-- |_  physName: MB420SAVad0UFPE0BNW
author = "Maarten Wallraf"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}


portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})


local function process_walk_table( tbl, base_oid )
  local result = stdnse.output_table()
  for _, v in ipairs( tbl ) do
    if v.oid == string.format("%s.1.0", base_oid) and result["sysDescr"] == nil then
      result.sysDescr = v.value
    end    
    if v.oid == string.format("%s.2.0", base_oid) and result["sysObjectId"] == nil then
      result.sysObjectId = snmp.oid2str(v.value)
    end
    if v.oid == string.format("%s.3.0", base_oid) and result["sysUpTime"] == nil then
      result.sysUpTime = string.format("%s (%s timeticks)", datetime.format_time(v.value, 100), tostring(v.value))
    end
    if v.oid == string.format("%s.4.0", base_oid) and result["sysContact"] == nil then
      result.sysContact = v.value
    end
    if v.oid == string.format("%s.5.0", base_oid) and result["sysName"] == nil then
      result.sysName = v.value
    end
    if v.oid == string.format("%s.6.0", base_oid) and result["sysLocation"] == nil then
      result.sysLocation = v.value
    end

  end
  return result
end


local function process_walk_table_ciena( tbl, base_oid )
  local result = stdnse.output_table()
  for _, v in ipairs( tbl ) do
    if v.oid == string.format("%s.1.0", base_oid) and result["sysDescr"] == nil then
      result.sysDescr = v.value
    end    
    if v.oid == string.format("%s.2.0", base_oid) and result["sysObjectId"] == nil then
      result.sysObjectId = snmp.oid2str(v.value)
    end
    if v.oid == string.format("%s.3.0", base_oid) and result["sysUpTime"] == nil then
      result.sysUpTime = string.format("%s (%s timeticks)", datetime.format_time(v.value, 100), tostring(v.value))
    end
    if v.oid == string.format("%s.4.0", base_oid) and result["sysContact"] == nil then
      result.sysContact = v.value
    end
    if v.oid == string.format("%s.5.0", base_oid) and result["sysName"] == nil then
      result.sysName = v.value
    end
    if v.oid == string.format("%s.6.0", base_oid) and result["sysLocation"] == nil then
      result.sysLocation = v.value
    end

  end
  return result
end

local function table_merge( t1, t2 )
  for _, v in ipairs(t2) do
    table.insert(t1, v)
  end
  return t1
end


---
-- Sends SNMP packets to host and reads responses
---
action = function(host, port)

  local oidSystem = "1.3.6.1.2.1.1"

  local oidName = "1.3.6.1.2.1.47.1.1.1.1.2.1"
  local oidDescrption = "1.3.6.1.2.1.47.1.1.1.1.2.1"
  local oidModel = "1.3.6.1.2.1.47.1.1.1.1.13.1"
  local oidSerial = "1.3.6.1.2.1.47.1.1.1.1.11.1"
  local oidSoftware = "1.3.6.1.2.1.47.1.1.1.1.10.1"

  -- Ciena WWP
  local oidCiena = "1.3.6.1.4.1.6141"
  local oidCienaSerial = "1.3.6.1.4.1.6141.2.60.11.1.1.1.67.0"
  local oidCienaChassisName = "1.3.6.1.4.1.6141.2.60.11.1.1.8.52.0"
  local oidCienaChassisDescr = "1.3.6.1.4.1.6141.2.60.11.1.1.8.53.0"
  local oidCienaRunSoftware = "1.3.6.1.4.1.6141.2.60.10.1.1.3.1.2.1"

  -- checks for arguments: snmp.timeout,snmp.version
  local snmp_timeout = stdnse.get_script_args({"snmp.timeout", "timeout"}) or 5000
  local snmp_version = stdnse.get_script_args({"snmp.version", "version"}) or "v2c"
  local snmp_options = {timeout=snmp_timeout, version=snmp_version}

  local snmpHelper = snmp.Helper:new(host, port, nil, snmp_options)


  local status, result
  
  -- sysInfo
  snmpHelper:connect()
  status, result = snmpHelper:walk(oidSystem)
  if ( not(status) ) then return end

  if ( result == nil ) or ( #result == 0 ) then
    return
  end
  local results = process_walk_table(result, oidSystem)

  -- since we got something back, the port is definitely open
  nmap.set_port_state(host, port, "open")

  -- physicalInfo -- serial
  snmpHelper:connect()
  status, result = snmpHelper:get({}, oidSerial)
  if (status and result and result[1] and result[1][1]) then
    results.physSerial = result[1][1]

    -- only do additional get requests if serial is known

    -- physicalInfo -- software
    snmpHelper:connect()
    status, result = snmpHelper:get({}, oidSoftware)
    if (status and result and result[1] and result[1][1]) then
      results.physSoftware = result[1][1]
    end

    -- physicalInfo -- model
    snmpHelper:connect()
    status, result = snmpHelper:get({}, oidModel)
    if (status and result and result[1] and result[1][1]) then
      results.physModel = result[1][1]
    end

    -- physicalInfo -- description
    snmpHelper:connect()
    status, result = snmpHelper:get({}, oidModel)
    if (status and result and result[1] and result[1][1]) then
      results.physDescription = result[1][1]
    end

    -- physicalInfo -- name
    snmpHelper:connect()
    status, result = snmpHelper:get({}, oidName)
    if (status and result and result[1] and result[1][1]) then
      results.physName = result[1][1]
    end

  end



  -- ciena WWP
  if (results and results.sysObjectId and results.sysObjectId:sub(1, #oidCiena) == oidCiena) then
    snmpHelper:connect()
    status, result = snmpHelper:get({}, oidCienaSerial)
    if (status and result and result[1] and result[1][1]) then
      results.physSerial = result[1][1]

      -- physicalInfo -- software
      snmpHelper:connect()
      status, result = snmpHelper:get({}, oidCienaRunSoftware)
      if (status and result and result[1] and result[1][1]) then
        results.physSoftware = result[1][1]
      end

      -- physicalInfo -- model
      --snmpHelper:connect()
      --status, result = snmpHelper:get({}, oidModel)
      --if (status and result and result[1] and result[1][1]) then
      --  results.physModel = result[1][1]
      --end

      -- physicalInfo -- description
      snmpHelper:connect()
      status, result = snmpHelper:get({}, oidCienaChassisDescr)
      if (status and result and result[1] and result[1][1]) then
        results.physDescription = result[1][1]
      end

      -- physicalInfo -- name
      snmpHelper:connect()
      status, result = snmpHelper:get({}, oidCienaChassisName)
      if (status and result and result[1] and result[1][1]) then
        results.physName = result[1][1]
      end

    end
  end



  return results
end
