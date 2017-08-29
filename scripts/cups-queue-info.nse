local ipp = require "ipp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local unpwdb = require "unpwdb"

description = [[
Lists currently queued print jobs of the remote CUPS service grouped by
printer.
]]

---
-- @usage
-- nmap -p 631 <ip> --script cups-queue-info
--
-- @output
-- PORT    STATE SERVICE
-- 631/tcp open  ipp
-- | cups-queue-info:
-- |   HP Laserjet
-- |     id  time                 state  size (kb)  owner            jobname
-- |     14  2012-04-26 22:01:19  Held   2071k      Patrik Karlsson  Print - CUPS Implementation of IPP - Documentation - CUPS
-- |   Generic-PostScript-Printer
-- |     id  time                 state    size (kb)  owner    jobname
-- |     3   2012-04-16 23:25:47  Pending  11k        Unknown  Unknown
-- |     4   2012-04-16 23:33:21  Pending  11k        Unknown  Unknown
-- |_    11  2012-04-24 08:15:14  Pending  13k        Unknown  Unknown
--

categories = {"safe", "discovery"}

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}


portrule = shortport.port_or_service(631, "ipp", "tcp", "open")

action = function(host, port)
  local helper = ipp.Helper:new(host, port)
  if ( not(helper:connect()) ) then
    return stdnse.format_output(false, "Failed to connect to server")
  end

  local output, results = helper:getQueueInfo()

  for _, printer in pairs(results) do
    unpwdb.add_phrase(host, printer["owner"])
    unpwdb.add_phrase(host, printer["jobname"])
  end
  if ( output ) then
    return stdnse.format_output(true, output)
  end
end
