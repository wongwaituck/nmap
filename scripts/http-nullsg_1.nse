local shortport = require "shortport"

description = [[
This script detects the LFI vulnerability in I Love Information Security.
]]
categories = {"intrusive", "vuln", "exploit"}
author = "Wai Tuck <waituck@edgis-security.org"
license = "Same as Nmap---See https://nmap.org/book/man-legal.html"
portrule = shortport.http

action = function(host, port)
  return "Null SG rocks"
end
