-- nmap NSE script: /usr/share/nmap/scripts/snmp-ifalias-service.nse
-- nmap -sU -p 22,23,161 -PE -PS22,23 -T4 -n --script snmp-brute,snmp-ifalias-service  --script-args snmp-brute.communitiesdb=/tmp/communities,snmp.timeout=2000 10.0.96.1 10.0.32.1 -vvv -d -oX /tmp/test.xml

local datetime = require "datetime"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local string = require "string"
local stdnse = require "stdnse"

description = [[
Finds all the services (ex. VT123123) from the interface aliases using SNMP and returns them in the format: ifName = <services>. It also lists all interfaces that have services or IP addresses, along with their subnet masks. Use in combination with snmp-brute.
]]

author = "Maarten Wallraf"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

-- SNMP OIDs for interface names, aliases, IP addresses, subnet masks, and interface indices
local ifAliasOID = "1.3.6.1.2.1.31.1.1.1.18"  -- ifAlias
local ifNameOID = "1.3.6.1.2.1.31.1.1.1.1"   -- ifName
local ipAddrOID = "1.3.6.1.2.1.4.20.1.1"     -- IP address
local subnetMaskOID = "1.3.6.1.2.1.4.20.1.3" -- Subnet mask
local ipAddrIfIndexOID = "1.3.6.1.2.1.4.20.1.2" -- IP to interface index mapping

action = function(host, port)

  local results = {}
  local ip_addresses = {}  -- Table to store IP addresses and masks by ifIndex
  local valid_ifIndexes = {}  -- Table to store valid ifIndexes from ifNameOID

  local snmp_timeout = stdnse.get_script_args({"snmp.timeout", "timeout"}) or 5000
  local snmp_version = stdnse.get_script_args({"snmp.version", "version"}) or "v2c"
  local snmp_options = {timeout=snmp_timeout, version=snmp_version}

  local snmp_helper = snmp.Helper:new(host, port, nil, snmp_options)

  if not snmp_helper then
    return "Failed to establish SNMP session."
  end

  local pattern = "VT%d+"
  local custom_pattern = stdnse.get_script_args("snmp-ifalias.regex")
  if custom_pattern then
    pattern = custom_pattern
  end

  -- Perform SNMP walk to get the ifAlias descriptions, IP addresses, subnet masks, and interface indices
  snmp_helper:connect()
  local status, ifAlias = snmp_helper:walk(ifAliasOID)
  local ifNameStatus, ifNames = snmp_helper:walk(ifNameOID)
  local ipStatus, ipAddrs = snmp_helper:walk(ipAddrOID)
  local maskStatus, subnetMasks = snmp_helper:walk(subnetMaskOID)
  local ifIndexStatus, ipAddrIfIndex = snmp_helper:walk(ipAddrIfIndexOID)

  if (not status) or (not ifNameStatus) or (not ifAlias) or (not ifNames) or (not ifIndexStatus) then
    return "Failed to fetch SNMP data."
  end

  stdnse.debug1("SNMP walk of IF-MIB returned %d aliases, %d names, %d IP addresses, and %d subnet masks",
                #ifAlias, #ifNames, #ipAddrs, #subnetMasks)

  -- Store valid ifIndexes from the ifNames walk
  for _, name_oid in pairs(ifNames) do
    local if_index = tostring(name_oid.oid):match("(%d+)$")  -- Use the actual OID
    if if_index then
      valid_ifIndexes[if_index] = true
    end
  end

  -- DEBUG: Print valid ifIndexes
  stdnse.debug1("DEBUG: Valid ifIndexes from ifNameOID:")
  for if_index, _ in pairs(valid_ifIndexes) do
    stdnse.debug1("Valid ifIndex: %s", tostring(if_index))
  end

  -- Store IP addresses and subnet masks only for valid ifIndexes
  for ip_oid, if_index_data in pairs(ipAddrIfIndex) do
    local if_index = tostring(if_index_data.value)  -- Ensure the if_index is a string

    -- Only proceed if the if_index is valid
    if valid_ifIndexes[if_index] then
      -- Use the OID from ipAddrOID to get the correct IP address and subnet mask
      local ip_addr = ipAddrs[ip_oid] and ipAddrs[ip_oid].value or nil  -- Check if IP address exists
      local subnet_mask = subnetMasks[ip_oid] and subnetMasks[ip_oid].value or nil -- Check if subnet mask exists

      -- DEBUG: Print IP and subnet mask as they are being stored
      stdnse.debug1("Storing IP address and subnet mask for valid ifIndex %s: IP=%s, Mask=%s", if_index, tostring(ip_addr), tostring(subnet_mask))

      if ip_addr then
        ip_addresses[if_index] = {ip = ip_addr, mask = subnet_mask or "Unknown"}  -- Use "Unknown" if mask is nil
      end
    else
      -- DEBUG: Log if the if_index is not valid
      stdnse.debug1("Skipping IP address for invalid ifIndex %s", tostring(if_index))
    end
  end

  -- Match ifAlias and ifName
  for _, alias in pairs(ifAlias) do
    local alias_value = alias.value

    -- Ensure oid is treated as a string and get the index
    local oid_str = tostring(alias.oid)
    local if_index = oid_str:match("(%d+)$")
    
    if if_index then
      local ifName_oid = ifNameOID .. "." .. if_index

      -- Debugging: Print expected ifName_oid to ensure it's being constructed correctly
      stdnse.debug1("Constructed ifName_oid: %s", ifName_oid)

      -- Now match with ifNames using a more reliable approach
      local ifName = nil
      for _, name_data in pairs(ifNames) do
        local name_oid = tostring(name_data.oid)  -- Convert to string to avoid issues
        if name_oid:find(if_index .. "$") then  -- Match by interface index
          ifName = name_data.value
          break
        end
      end

      if not ifName then
        ifName = "Unknown"
      end

      -- Get the IP and subnet mask
      local ip_info = ip_addresses[if_index]
      local ip_str = ""
      if ip_info then
        ip_str = string.format(" (IP: %s, Subnet Mask: %s)", ip_info.ip, ip_info.mask)
      else
        -- DEBUG: Log if no IP info is found for this ifIndex
        stdnse.debug1("No IP info found for ifIndex %s", tostring(if_index))
      end

      -- Check if alias contains the service pattern
      local services = {}
      if alias_value then
        for service in alias_value:gmatch(pattern) do
          table.insert(services, service)
        end
      end

      -- Add interfaces with services or IP addresses
      if #services > 0 or ip_info then
        local result_str = ifName .. " = "
        if #services > 0 then
          result_str = result_str .. table.concat(services, ", ")
        else
          result_str = result_str .. "<No services>"
        end
        result_str = result_str .. ip_str  -- Append IP and subnet mask
        table.insert(results, result_str)
      end
    end
  end

  -- Return the results or a message if none are found
  if #results > 0 then
    return table.concat(results, "\n")
  else
    return "No services found in ifAlias."
  end
end


