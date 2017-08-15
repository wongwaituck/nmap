---
-- Username/password database library.
--
-- The <code>usernames</code> and <code>passwords</code> functions return
-- multiple values for use with exception handling via
-- <code>nmap.new_try</code>. The first value is the Boolean success
-- indicator, the second value is the closure.
--
-- The closures can take an argument of <code>"reset"</code> to rewind the list
-- to the beginning.
--
-- To avoid taking a long time against slow services, the closures will
-- stop returning values (start returning <code>nil</code>) after a
-- certain time. The time depends on the timing template level, and is
-- * <code>-T3</code> or less: 10 minutes
-- * <code>-T4</code>: 5 minutes
-- * <code>-T5</code>: 3 minutes
-- Time limits are increased by 50% if a custom username or password
-- database is used with the <code>userdb</code> or <code>passdb</code>
-- script arguments. You can control the time limit directly with the
-- <code>unpwdb.timelimit</code> script argument. Use
-- <code>unpwdb.timelimit=0</code> to disable the time limit.
--
-- You can select your own username and/or password database to read from with
-- the script arguments <code>userdb</code> and <code>passdb</code>,
-- respectively.  Comments are allowed in these files, prefixed with
-- <code>"#!comment:"</code>.  Comments cannot be on the same line as a
-- username or password because this leaves too much ambiguity, e.g. does the
-- password in <code>"mypass  #!comment: blah"</code> contain a space, two
-- spaces, or do they just separate the password from the comment?
--
-- @usage
-- require("unpwdb")
--
-- local usernames, passwords
-- local try = nmap.new_try()
--
-- usernames = try(unpwdb.usernames())
-- passwords = try(unpwdb.passwords())
--
-- for password in passwords do
--   for username in usernames do
--     -- Do something with username and password.
--   end
--   usernames("reset")
-- end
--
-- @usage
-- nmap --script-args userdb=/tmp/user.lst
-- nmap --script-args unpwdb.timelimit=10m
--
-- @args userdb The filename of an alternate username database. Default: nselib/data/usernames.lst
-- @args passdb The filename of an alternate password database. Default: nselib/data/passwords.lst
-- @args unpwdb.userlimit The maximum number of usernames
-- <code>usernames</code> will return (default unlimited).
-- @args unpwdb.passlimit The maximum number of passwords
-- <code>passwords</code> will return (default unlimited).
-- @args unpwdb.timelimit The maximum amount of time that any iterator will run
-- before stopping. The value is in seconds by default and you can follow it
-- with <code>ms</code>, <code>s</code>, <code>m</code>, or <code>h</code> for
-- milliseconds, seconds, minutes, or hours. For example,
-- <code>unpwdb.timelimit=30m</code> or <code>unpwdb.timelimit=.5h</code> for
-- 30 minutes. The default depends on the timing template level (see the module
-- description). Use the value <code>0</code> to disable the time limit.
-- @author Kris Katterjohn 06/2008, Wong Wai Tuck 08/2017
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local io = require "io"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
_ENV = stdnse.module("unpwdb", stdnse.seeall)

local usertable = {}
local passtable = {}

local profiled_table = {}
local stopwords_table = {}

--- fills the table with the contents of the file, delimited by new lines
--  the file will use "#!comment:" for comments
--  @param filename the string containing the full path to the file to be loaded
--  @param table the table to be loaded with the contents
--  @param lower_case boolean indicating whether to standardize to lower case
--  default: false, i.e. contents wll be loaded as is
local filltable = function(filename, table, lower_case)
  if #table ~= 0 then
    return true
  end

  local file = io.open(filename, "r")

  if not file then
    return false
  end

  for l in file:lines() do
    -- Comments takes up a whole line
    if not l:match("#!comment:") then
      if lower_case then
        table[#table + 1] = l:lower()
      else
        table[#table + 1] = l
      end
    end
  end

  file:close()

  return true
end

--- loads stop words, optionally from a file
--  @return status indicating success or failure in loading the stopword table
local function load_stop_words()
  local stopword_file = stdnse.get_script_args('stopwordlst') or
    nmap.fetchfile("nselib/data/stopwords_en.lst")
  local err

  if stopword_file then
    local status = filltable(stopword_file ,stopwords_table, true)
    if not status then
      err = "Stopword file loading failed!"
      stdnse.debug2(err)
      return false, err
    end
  else
    err = "Stopword file not found!"
    stdnse.debug2(err)
    return false
  end

  return true
end

--- saves a word verbatim to the password profile table
--  @param host the target host object that you wish to associate the word
--  @param keyword the profiling keyword that is associated with the host
--  @return boolean representing whether the keyword was associated
--  @return error the error if the adding was unsuccessful
function add_word(host, keyword)
  local disabled = stdnse.get_script_args('unpwdb.disable_profile')

  -- if the disable profile is on we don't add any words to the profiling table
  if disabled and (disabled ~= 'false' or disabled ~= 'False') then
    return
  end

  local export_file = stdnse.get_script_args('unpwdb.export_file')
  local f, err

  if export_file ~= nil and #export_file > 0 then
    f, err = io.open(export_file, "a")
    if not f then
      stdnse.debug2("Error saving \"%s\" to %s: %s\n", keyword, export_file, err)
      return f, err
    end
  end

  -- naive adding for now
  -- TODO: process for subnet based scanning
  -- do not insert duplicates inside the profiling!
  if not stdnse.contains(profiled_table, keyword) then
    table.insert(profiled_table, keyword)
    if f then
      f:write(keyword)
      f:close()
    end
  end
end

--- parses a phrase for unique words, with an option to include stop words
--  @param host the target host object that you wish to associate the words
--  @param phrase the whole phrase that you wish to parse
--  @param separator the character that you wish to separate the phrase,
--  default: any whitespace character, optional
--  @param include_stop_words a boolean indicating whether to include stopwords
--  default: false, optional
--  @return boolean representing whether the keywords were associated
--  @return words the array of words added to the password profile, or nil
--  @return error the error if the adding was unsuccessful
function add_phrase(host, phrase, separator, include_stop_words)
  local words = {}

  if not include_stop_words then
    local status = load_stop_words()
    if not status then
      return false, nil, err
    end
  end

  if phrase and #phrase > 0 then
    if separator == nil then
      -- match all non whitespace characters
      for word in phrase:gmatch("%S+") do
        local l_word = word:lower()
        -- only add word if choose to include stopwords so no check OR
        -- it passes the check of not being inside the stopwords table
        if include_stop_words or not stdnse.contains(stopwords_table, l_word) then
          local status, err = add_word(host, word)
          if not status then
            stdnse.debug2("Error occured while adding word to pwdprofile: %s",
              err)
            return status, nil, err
          else
            table.insert(words, word)
          end
        end
      end
    else
    -- use the separator in the processing
    -- haven't figured out the logic for this yet
    end
  end
  return true, words, nil
end

local customdata = false

-- So I don't have to type as much :)
local args = nmap.registry.args

local userfile = function()
  if args.userdb then
    customdata = true
    return args.userdb
  end

  return nmap.fetchfile("nselib/data/usernames.lst")
end

local passfile = function()
  if args.passdb then
    customdata = true
    return args.passdb
  end

  return nmap.fetchfile("nselib/data/passwords.lst")
end

table_iterator = function(table)
  local h = 1
  local i = 1

  return function(cmd)
    if cmd == "reset" then
      h = 1
      i = 1
      return
    end

    -- iterate through the profiling table first
    local prof_elem = profiled_table[h]
    if prof_elem then
      h = h + 1
    else
      -- no more elements
      -- now iterate through the actual table, whatever it is
      local elem = table[i]
      if elem then i = i + 1 end
      return elem
    end
  end
end

--- Returns the suggested number of seconds to attempt a brute force attack
--
-- Based on the <code>unpwdb.timelimit</code> script argument, Nmap's timing
-- values (<code>-T4</code> etc.) and whether or not a user-defined list is
-- used.
--
-- You can use the script argument <code>notimelimit</code> to make this
-- function return <code>nil</code>, which means the brute-force should run
-- until the list is empty. If <code>notimelimit</code> is not used, be sure to
-- still check for <code>nil</code> return values on the above two functions in
-- case you finish before the time limit is up.
timelimit = function()
  -- If we're reading from a user-defined username or password list,
  -- we'll give them a timeout 1.5x the default.  If the "notimelimit"
  -- script argument is used, we return nil.
  local t = nmap.timing_level()

  -- Easy enough
  if args.notimelimit then
    return nil
  end
  if args["unpwdb.timelimit"] then
    local limit, err = stdnse.parse_timespec(args["unpwdb.timelimit"])
    if not limit then
      error(err)
    end
    return limit
  end

  if t <= 3 then
    return (customdata and 900) or 600
  elseif t == 4 then
    return (customdata and 450) or 300
  elseif t == 5 then
    return (customdata and 270) or 180
  end
end

--- Returns a function closure which returns a new username with every call
-- until the username list is exhausted (in which case it returns
-- <code>nil</code>).
-- @return boolean Status.
-- @return function The usernames iterator.
local usernames_raw = function()
  local path = userfile()

  if not path then
    return false, "Cannot find username list"
  end

  if not filltable(path, usertable) then
    return false, "Error parsing username list"
  end

  return true, table_iterator(usertable)
end

--- Returns a function closure which returns a new password with every call
-- until the password list is exhausted (in which case it returns
-- <code>nil</code>).
-- @return boolean Status.
-- @return function The passwords iterator.
local passwords_raw = function()
  local path = passfile()

  if not path then
    return false, "Cannot find password list"
  end

  if not filltable(path, passtable) then
    return false, "Error parsing password list"
  end

  return true, table_iterator(passtable)
end

--- Wraps time and count limits around an iterator.
--
-- When either limit expires, starts returning <code>nil</code>. Calling the
-- iterator with an argument of "reset" resets the count.
-- @param time_limit Time limit in seconds. Use 0 or <code>nil</code> for no limit.
-- @param count_limit Count limit in seconds. Use 0 or <code>nil</code> for no limit.
-- @return boolean Status.
-- @return function The wrapped iterator.
limited_iterator = function(iterator, time_limit, count_limit)
  local start, count, elem

  time_limit = (time_limit and time_limit > 0) and time_limit
  count_limit = (count_limit and count_limit > 0) and count_limit

  start = os.time()
  count = 0
  return function(cmd)
    if cmd == "reset" then
      count = 0
    else
      count = count + 1
    end
    if count_limit and count > count_limit then
      return
    end
    if time_limit and os.time() - start >= time_limit then
      return
    end
    return iterator(cmd)
  end
end

--- Returns a function closure which returns a new password with every call
-- until the username list is exhausted or either limit expires (in which cases
-- it returns <code>nil</code>).
-- @param time_limit Time limit in seconds. Use 0 for no limit.
-- @param count_limit Count limit in seconds. Use 0 for no limit.
-- @return boolean Status.
-- @return function The usernames iterator.
usernames = function(time_limit, count_limit)
  local status, iterator

  status, iterator = usernames_raw()
  if not status then
    return false, iterator
  end

  time_limit = time_limit or timelimit()
  if not count_limit and args["unpwdb.userlimit"] then
    count_limit = tonumber(args["unpwdb.userlimit"])
  end

  return true, limited_iterator(iterator, time_limit, count_limit)
end

--- Returns a function closure which returns a new password with every call
-- until the password list is exhausted or either limit expires (in which cases
-- it returns <code>nil</code>).
-- @param time_limit Time limit in seconds. Use 0 for no limit.
-- @param count_limit Count limit in seconds. Use 0 for no limit.
-- @return boolean Status.
-- @return function The passwords iterator.
passwords = function(time_limit, count_limit)
  local status, iterator

  status, iterator = passwords_raw()
  if not status then
    return false, iterator
  end

  time_limit = time_limit or timelimit()
  if not count_limit and args["unpwdb.passlimit"] then
    count_limit = tonumber(args["unpwdb.passlimit"])
  end

  return true, limited_iterator(iterator, time_limit, count_limit)
end

--- Returns a new iterator that iterates through its consecutive iterators,
-- basically concatenating them.
-- @param iter1 First iterator to concatenate.
-- @param iter2 Second iterator to concatenate.
-- @return function The concatenated iterators.
function concat_iterators (iter1, iter2)
  local function helper (next_iterator, command, first, ...)
    if first ~= nil then
      return first, ...
    elseif next_iterator ~= nil then
      return helper(nil, command, next_iterator(command))
    end
  end
  local function iterator (command)
    if command == "reset" then
      iter1 "reset"
      iter2 "reset"
    else
      return helper(iter2, command, iter1(command))
    end
  end
  return iterator
end

--- Returns a new iterator that filters its results based on the filter.
-- @param iterator Iterator that needs to be filtered
-- @param filter Function that returns bool, which serves as a filter
-- @return function The filtered iterator.
function filter_iterator (iterator, filter)
  return function (command)
    if command == "reset" then
      iterator "reset"
    else
      local val = iterator(command)
      while val and not filter(val) do
        val = iterator(command)
      end
      return val
    end
  end
end

return _ENV;
