-- nmap NSE script: /usr/share/nmap/scripts/snmp-ifalias-service.nse
-- nmap -sU -p 22,23,161 -PE -PS22,23 -T4 -n --script snmp-brute,snmp-ifalias-service --script-args snmp-brute.communitiesdb=/tmp/communities,snmp.timeout=2000 10.0.96.1 10.0.32.1 -vvv -d -oX /tmp/test.xml

local creds = require "creds"
local ipOps = require "ipOps"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
Finds all the services (ex. VT123123) in the interface aliases (ifAlias) using
SNMP. Lists every interface that has services or IPv4 addresses, with its
ifIndex, alias, services and addresses. Use in combination with snmp-brute.

The script only polls when a community string is known for the port (found by
snmp-brute or given with creds.snmp) or when nmap already received an SNMP
reply on it. The interface and address tables are walked together with GETBULK
requests (SNMPv2c) or GETNEXT requests (SNMPv1).
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-ifalias-service --script-args creds.snmp=<community> <target>
-- nmap -sU -p 161 --script snmp-brute,snmp-ifalias-service --script-args snmp-brute.communitiesdb=comms.txt <target>
--
-- @args snmp-ifalias-service.pattern Lua pattern that matches a service in the
--       interface alias (default: <code>VT%d+</code>). The old argument name
--       <code>snmp-ifalias.regex</code> is also accepted.
-- @args snmp-ifalias-service.maxrepetitions Rows requested per GETBULK
--       request (default: 25)
-- @args snmp.timeout SNMP timeout per request in milliseconds (default: 5000)
-- @args snmp.version SNMP version, v1 or v2c (default: v2c)
--
-- @output
-- | snmp-ifalias-service:
-- |   GigabitEthernet0/0/1:
-- |     ifIndex: 5
-- |     ifAlias: uplink core-01
-- |     addresses:
-- |       10.0.0.1/24
-- |       172.16.0.1/30
-- |   GigabitEthernet0/0/2.100:
-- |     ifIndex: 12
-- |     ifAlias: VT123456 customer-a VT123457
-- |     services:
-- |       VT123456
-- |_      VT123457
--
-- @xmloutput
-- <table key="GigabitEthernet0/0/1">
--   <elem key="ifIndex">5</elem>
--   <elem key="ifAlias">uplink core-01</elem>
--   <table key="addresses">
--     <elem>10.0.0.1/24</elem>
--     <elem>172.16.0.1/30</elem>
--   </table>
-- </table>
-- <table key="GigabitEthernet0/0/2.100">
--   <elem key="ifIndex">12</elem>
--   <elem key="ifAlias">VT123456 customer-a VT123457</elem>
--   <table key="services">
--     <elem>VT123456</elem>
--     <elem>VT123457</elem>
--   </table>
-- </table>

author = "Maarten Wallraf"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

local IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"     -- IF-MIB ifName
local IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"   -- IF-MIB ifAlias
local IP_IFINDEX = "1.3.6.1.2.1.4.20.1.2"    -- IP-MIB ipAdEntIfIndex, indexed by IP address
local IP_NETMASK = "1.3.6.1.2.1.4.20.1.3"    -- IP-MIB ipAdEntNetMask, indexed by IP address


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

-- The snmp library has no GETBULK request: it has the same layout as GETNEXT,
-- with non-repeaters and max-repetitions in place of error-status and
-- error-index.
local function build_getbulk(max_repetitions, oids)
  local pdu = snmp.buildGetNextRequest({}, table.unpack(oids))
  pdu._snmp = "\xa5"
  pdu[2] = 0
  pdu[3] = max_repetitions
  return pdu
end

-- Walks several table columns side by side, so one request returns the next
-- rows of all of them. Returns a status and, per column, a table that maps the
-- row index (OID suffix) to the value. The status is false when the agent
-- stopped answering; the result then holds the rows read so far.
local function walk_columns(helper, bases, use_bulk, max_repetitions)
  local columns, result = {}, {}
  for i, base in ipairs(bases) do
    columns[i] = {prefix = base .. ".", last = base, rows = {}}
    result[i] = columns[i].rows
  end

  local active = columns
  while #active > 0 do
    local oids = {}
    for i, column in ipairs(active) do
      oids[i] = column.last
    end
    local pdu = use_bulk and build_getbulk(max_repetitions, oids)
                or snmp.buildGetNextRequest({}, table.unpack(oids))
    local status, raw = helper:request(pdu)
    if not status then
      return false, result
    end
    local err, erridx, varbinds = parse_response(raw)
    if not err then
      return false, result
    end

    if err == 1 and use_bulk and max_repetitions > 1 then
      -- tooBig: ask for fewer rows
      max_repetitions = max_repetitions // 2
    elseif err == 2 and active[erridx] then
      -- SNMPv1 noSuchName: that column reached the end of the MIB
      active[erridx].done = true
    elseif err ~= 0 then
      stdnse.debug1("walk failed with error-status %d", err)
      return false, result
    else
      -- varbinds come row by row: column 1, 2, ..., n, column 1, 2, ...
      local progress = false
      for k, varbind in ipairs(varbinds) do
        local column = active[(k - 1) % #active + 1]
        local value, oid = varbind[1], varbind[2]
        if column.done then
          -- column ended earlier in this response
        elseif value == nil or oid:sub(1, #column.prefix) ~= column.prefix then
          -- endOfMibView or past the end of the column
          column.done = true
        elseif oid ~= column.last then
          if value ~= false then
            column.rows[oid:sub(#column.prefix + 1)] = value
          end
          column.last = oid
          progress = true
        end
      end
      if not progress then
        break
      end
    end

    local remaining = {}
    for _, column in ipairs(active) do
      if not column.done then
        remaining[#remaining + 1] = column
      end
    end
    active = remaining
  end
  return true, result
end

-- "10.0.0.1", "255.255.255.0" -> "10.0.0.1/24"; non-contiguous masks are
-- kept in dotted notation.
local function format_address(ip, mask)
  if type(mask) ~= "string" then
    return ip
  end
  local bits, seen_zero = 0, false
  for octet in mask:gmatch("%d+") do
    local n = tonumber(octet)
    for bit = 7, 0, -1 do
      if n & (1 << bit) ~= 0 then
        if seen_zero then
          return ip .. "/" .. mask
        end
        bits = bits + 1
      else
        seen_zero = true
      end
    end
  end
  return ip .. "/" .. bits
end

local function by_ifindex(a, b)
  return tonumber(a) < tonumber(b)
end

local function by_address(a, b)
  return ipOps.compare_ip(a:match("^[^/]+"), "lt", b:match("^[^/]+"))
end


action = function(host, port)

  if not have_community(host, port) then
    stdnse.debug1("no SNMP community known for %s, skipping", host.ip)
    return nil
  end

  local pattern = stdnse.get_script_args({SCRIPT_NAME .. ".pattern", "snmp-ifalias.regex"}) or "VT%d+"
  local max_repetitions = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxrepetitions")) or 25
  local options = snmp_options()
  local use_bulk = options.version ~= "v1" and tostring(options.version) ~= "0"

  local helper = snmp.Helper:new(host, port, nil, options)
  if not helper:connect() then
    return nil
  end
  local status, columns = walk_columns(helper, {IF_NAME, IF_ALIAS, IP_IFINDEX, IP_NETMASK},
                                       use_bulk, max_repetitions)
  helper.socket:close()
  if not status then
    stdnse.debug1("SNMP walk of %s did not complete", host.ip)
    return nil
  end
  local names, aliases, ip_ifindex, netmasks = table.unpack(columns)

  -- the row index of the address table is the IP address itself
  local addresses = {}
  for ip, ifindex in pairs(ip_ifindex) do
    ifindex = tostring(ifindex)
    if names[ifindex] then
      addresses[ifindex] = addresses[ifindex] or {}
      table.insert(addresses[ifindex], format_address(ip, netmasks[ip]))
    else
      stdnse.debug2("skipping %s: ifIndex %s has no ifName", ip, ifindex)
    end
  end

  local ifindexes = {}
  for ifindex in pairs(names) do
    ifindexes[#ifindexes + 1] = ifindex
  end
  table.sort(ifindexes, by_ifindex)

  local results = stdnse.output_table()
  local used_keys = {}
  local found = false
  for _, ifindex in ipairs(ifindexes) do
    local alias = aliases[ifindex]
    local services = {}
    if type(alias) == "string" then
      for service in alias:gmatch(pattern) do
        services[#services + 1] = service
      end
    end
    local ips = addresses[ifindex]

    if #services > 0 or ips then
      local entry = stdnse.output_table()
      entry.ifIndex = tonumber(ifindex)
      if type(alias) == "string" and alias ~= "" then
        entry.ifAlias = alias
      end
      if #services > 0 then
        entry.services = services
      end
      if ips then
        table.sort(ips, by_address)
        entry.addresses = ips
      end

      -- ifName is normally unique, but fall back to the ifIndex if it is not
      local key = tostring(names[ifindex])
      if key == "" or used_keys[key] then
        key = string.format("%s (ifIndex %s)", key, ifindex)
      end
      used_keys[key] = true
      results[key] = entry
      found = true
    end
  end

  if found then
    return results
  end
  return nil
end
