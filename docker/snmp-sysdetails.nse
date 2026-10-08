-- nmap NSE script: /usr/share/nmap/scripts/snmp-sysdetails.nse
-- nmap -sU -p 22,23,161 -PE -PS22,23 -T4 -n --script snmp-brute,snmp-sysdetails,snmp-info --script-args snmp-brute.communitiesdb=/tmp/communities,snmp.timeout=2000 25.0.96.1 25.0.32.1 -vvv -d -oX /tmp/test.xml

local creds = require "creds"
local datetime = require "datetime"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
Get additional information from a device using SNMP. System information and platform information is gathered. Use in combination with "snmp-brute"

The script only polls when a community string is known for the port (found by
snmp-brute or given with creds.snmp) or when nmap already received an SNMP
reply on it. This avoids waiting for the SNMP timeout on every host that does
not answer.

All system values are fetched with a single GET request and all physical
values with a second one.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-sysdetails --script-args creds.snmp=<community> <target>
-- nmap -sU -p 161 --script snmp-brute,snmp-sysdetails --script-args snmp-brute.communitiesdb=comms.txt <target>
--
-- @args snmp.timeout SNMP timeout per request in milliseconds (default: 5000)
-- @args snmp.version SNMP version, v1 or v2c (default: v2c)
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
-- |   physDescription: LBB_140 chassis
-- |_  physName: MB420SAVad0UFPE0BNW
--
-- @xmloutput
-- <elem key="sysDescr">ONEOS16-MONO_FT-V5.2R2E7_HA8</elem>
-- <elem key="sysObjectId">1.3.6.1.4.1.13191.1.1.140</elem>
-- <elem key="sysUpTime">57d21h06m33.41s (500079341 timeticks)</elem>
-- <elem key="sysContact">test</elem>
-- <elem key="sysName">dops-lab-02.as47377.net</elem>
-- <elem key="sysLocation"></elem>
-- <elem key="physSerial">T1703006230033175</elem>
-- <elem key="physSoftware"></elem>
-- <elem key="physModel">LBB_140</elem>
-- <elem key="physDescription">LBB_140 chassis</elem>
-- <elem key="physName">MB420SAVad0UFPE0BNW</elem>
author = "Maarten Wallraf"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}


portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})


local function format_oid(value)
  if type(value) ~= "table" then
    return tostring(value)
  end
  return snmp.oid2str(value)
end

local function format_uptime(value)
  if type(value) ~= "number" then
    return tostring(value)
  end
  return string.format("%s (%s timeticks)", datetime.format_time(value, 100), tostring(value))
end

-- SNMPv2-MIB system group, in output order
local SYSTEM = {
  {name = "sysDescr",    oid = "1.3.6.1.2.1.1.1.0"},
  {name = "sysObjectId", oid = "1.3.6.1.2.1.1.2.0", format = format_oid},
  {name = "sysUpTime",   oid = "1.3.6.1.2.1.1.3.0", format = format_uptime},
  {name = "sysContact",  oid = "1.3.6.1.2.1.1.4.0"},
  {name = "sysName",     oid = "1.3.6.1.2.1.1.5.0"},
  {name = "sysLocation", oid = "1.3.6.1.2.1.1.6.0"},
}

-- output order of the physical fields
local PHYS_FIELDS = {"physSerial", "physSoftware", "physModel", "physDescription", "physName"}

-- ENTITY-MIB entPhysicalTable, entry 1
local ENTITY = {
  physSerial      = "1.3.6.1.2.1.47.1.1.1.1.11.1",
  physSoftware    = "1.3.6.1.2.1.47.1.1.1.1.10.1",
  physModel       = "1.3.6.1.2.1.47.1.1.1.1.13.1",
  physDescription = "1.3.6.1.2.1.47.1.1.1.1.2.1",
  physName        = "1.3.6.1.2.1.47.1.1.1.1.7.1",
}

-- Ciena WWP, used instead of ENTITY-MIB when the serial is found there
local CIENA_PREFIX = "1.3.6.1.4.1.6141."
local CIENA = {
  physSerial      = "1.3.6.1.4.1.6141.2.60.11.1.1.1.67.0",
  physSoftware    = "1.3.6.1.4.1.6141.2.60.10.1.1.3.1.2.1",
  physDescription = "1.3.6.1.4.1.6141.2.60.11.1.1.8.53.0",
  physName        = "1.3.6.1.4.1.6141.2.60.11.1.1.8.52.0",
}


local function snmp_options()
  local timeout = tonumber(stdnse.get_script_args({"snmp.timeout", "timeout"})) or 5000
  local version = stdnse.get_script_args({"snmp.version", "version"}) or "v2c"
  return {timeout = timeout, version = version}
end

-- Returns true when polling can succeed: a community is known for the port
-- (snmp-brute result or creds.snmp) or nmap already got an SNMP reply. Without
-- either, the port is only open|filtered and polling would just wait for the
-- timeout.
local function have_community(host, port)
  if port.state == "open" then
    return true
  end
  local store = creds.Credentials:new(creds.ALL_DATA, host, port)
  for _, state in ipairs({creds.State.PARAM, creds.State.VALID}) do
    if store:getCredentials(state)() then
      return true
    end
  end
  return false
end

-- Decodes a raw response. Returns error-status, error-index and the varbinds
-- as {value, oid} pairs, or nil when the response cannot be decoded.
local function parse_response(raw)
  local msg = snmp.decode(raw)
  local pdu = type(msg) == "table" and msg[3]
  if type(pdu) ~= "table" or pdu._snmp ~= "\xa2" then
    return nil
  end
  return pdu[2], pdu[3], snmp.fetchResponseValues(msg)
end

-- Fetches all OIDs with one GET request. Returns a table OID -> value without
-- the OIDs the agent does not have, or nil when the agent does not answer.
-- SNMPv1 rejects the whole request when one OID is unknown (noSuchName): that
-- OID is then dropped and the request repeated.
local function get_many(helper, oids)
  local pending = {table.unpack(oids)}
  local result = {}
  while #pending > 0 do
    local status, raw = helper:request(snmp.buildGetRequest({}, table.unpack(pending)))
    if not status then
      return nil
    end
    local err, erridx, varbinds = parse_response(raw)
    if not err then
      return nil
    end
    if err == 0 then
      for _, varbind in ipairs(varbinds) do
        -- nil: noSuchObject/noSuchInstance, false: NULL
        if varbind[1] ~= nil and varbind[1] ~= false then
          result[varbind[2]] = varbind[1]
        end
      end
      return result
    end
    if err ~= 2 or not pending[erridx] then
      stdnse.debug1("GET failed with error-status %d", err)
      return result
    end
    table.remove(pending, erridx)
  end
  return result
end

local function oid_list(fields)
  local oids = {}
  for _, oid in pairs(fields) do
    oids[#oids + 1] = oid
  end
  return oids
end

-- Returns the physical fields: ENTITY-MIB values, replaced by the Ciena WWP
-- values when the device is a Ciena and has a serial there.
local function get_physical(helper, is_ciena)
  local oids = oid_list(ENTITY)
  if is_ciena then
    for _, oid in ipairs(oid_list(CIENA)) do
      oids[#oids + 1] = oid
    end
  end

  local values = get_many(helper, oids) or {}
  local phys = {}
  for name, oid in pairs(ENTITY) do
    phys[name] = values[oid]
  end
  if is_ciena and values[CIENA.physSerial] then
    for name, oid in pairs(CIENA) do
      phys[name] = values[oid] or phys[name]
    end
  end
  return phys
end


---
-- Sends SNMP packets to host and reads responses
---
action = function(host, port)

  if not have_community(host, port) then
    stdnse.debug1("no SNMP community known for %s, skipping", host.ip)
    return nil
  end

  local helper = snmp.Helper:new(host, port, nil, snmp_options())
  if not helper:connect() then
    return nil
  end

  local oids = {}
  for i, field in ipairs(SYSTEM) do
    oids[i] = field.oid
  end
  local system = get_many(helper, oids)
  if not system or next(system) == nil then
    helper.socket:close()
    return nil
  end

  -- since we got something back, the port is definitely open
  nmap.set_port_state(host, port, "open")

  local results = stdnse.output_table()
  for _, field in ipairs(SYSTEM) do
    local value = system[field.oid]
    if value ~= nil then
      results[field.name] = field.format and field.format(value) or value
    end
  end

  local sysobjectid = results.sysObjectId or ""
  local is_ciena = sysobjectid:sub(1, #CIENA_PREFIX) == CIENA_PREFIX
  local phys = get_physical(helper, is_ciena)
  helper.socket:close()

  for _, name in ipairs(PHYS_FIELDS) do
    if phys[name] ~= nil then
      results[name] = phys[name]
    end
  end

  return results
end
