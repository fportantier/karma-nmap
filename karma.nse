local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Uses the Karma Query API to obtain information about public IP addresses.

There is no limit on requests to this service. However, the API key
needs to be obtained through free registration for this service:
<code>https://karma.securetia.com</code>
]]

---
-- @usage
-- nmap --script karma <target> --script-args karma.apikey=<KEY>
--
-- @args karma.apikey A sting specifying the api-key which
--       the user wants to use to access this service
--
-- @output
-- | karma: 
-- |   cc: PE
-- |   blacklists: uceprotect.level3,uceprotect.level1,uceprotect.level2,spamhaus.css,sorbs.web,bad.psky.me
-- |   asn: 6147
-- |   country: Peru
-- |   asname: Telefonica del Peru S.A.A.,PE
-- |   status: blacklisted
-- |_  rir: LACNIC
--

author = "Fabian Martinez Portantier"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}


hostrule = function(host)
  local is_private, err = ipOps.isPrivate( host.ip )
  if is_private then
    stdnse.debug1("not running: Private IP address of target: %s", host.ip)
    return false
  end

  api_key = stdnse.get_script_args(SCRIPT_NAME..".apikey")

  if not (type(api_key)=="string") then
    api_key = os.getenv("KARMA_APIKEY")
  end

  if not (type(api_key)=="string") then
    stdnse.debug1("not running: No Karma API key specified.")
    return false
  end

  return true
end


local karma = function(ip)

  local header = {}
  header["Authorization"] = api_key
  header["Content-Length"] = 0 
  header["Accept"] = "application/json"

  local response = http.get("karma.securetia.com", 443, "/q/ip/"..ip, { header = header })

  if not response.status then
    stdnse.debug1("error received, exiting")
    return false
  end

  if response.status ~= 200 then
    stdnse.debug1("received status "..response.status..", exiting")
    return false
  end

  local status, result = json.parse(response.body)

  if status ~= true then
    stdnse.debug1("no response, possibly a network problem.")
    return false
  end

  return result
end


action = function(host)

  local out = karma(host.ip)

  if not out then
    return nil
  end

  local result = {}

  for key,value in pairs(out) do
    if type(value) == 'table' then
      value = table.concat(value, ",")
    end
    table.insert(result, key .. ": " .. tostring(value))
  end

  return stdnse.format_output(true, result)
end

