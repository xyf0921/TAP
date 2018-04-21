--
-- Created by IntelliJ IDEA.
-- User: stubborn
-- Date: 1/7/17
-- Time: 12:31 AM
-- To change this template use File | Settings | File Templates.
--

local  logging = require"script.thirdparty.logging"

local function logfunc( _, level, message)
    local logPattern = "%date,xxx:LuaVirtualMachine:%level:%message\n"
    io.stderr:write(logging.prepareLogMsg(logPattern, os.date("%Y-%m-%d %H:%M:%S"), level, message))
    return true
end

return logging.new(logfunc)