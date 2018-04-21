local function clear()
	Context = {}
	logger:info("Clearing Context ...[DONE]")
end

local function ctxSet( key, value )
	Context [ key ] = value
end

local function ctxGet( key )
	return Context [ key ]
end

local function defaultContext()
	clear()

--	local env_json,_,err = json.decode(env)
--
--	if 'device' == env_json['mode'] then
--		ctxSet("pcap.source", "device")
--
--		if	nil == env_json['device'] then
--			logger:error('device not set')
--			os.exit(0)
--		else
--			ctxSet("pcap.device", env_json['device'])
--		end
--	else
--		ctxSet("pcap.source", "file")
--		if	nil == env_json['fname'] then
--			logger:error('Pcap file not set')
--			os.exit(0)
--		else
--			ctxSet("pcap.filePath", env_json['fname'])
--		end
--	end
--
--	ctxSet("pcap.promisc", 0 )
--	ctxSet("pcap.enableOnStartup", true)

--	ctxSet("pcap.source", "file")
--	ctxSet("pcap.device", "ens33")
--	ctxSet("pcap.filePath", "/mnt/hgfs/D/test.pcap")
--	ctxSet("pcap.filePath", "./test.pcap")
--	ctxSet("pcap.filePath", "./test_pcap.pcap")

	logger:info("Loading Defaul Context ...[DONE]")
end

local package = {}

package["ctx"]			= Context
package["clear"]		= clear
package["defaultCtx"]	= defaultContext
package["get"]			= ctxGet
package["set"]			= ctxSet

return package;
