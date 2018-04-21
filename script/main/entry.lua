logger      = require "script.main.log"
json 		= require "script.thirdparty.dkjson"
ctx 		= require "script.main.ctx"
pcap     	= require "script.main.pcap"
watcher     = require "script.main.watcher"
bit         = require "bit32"

ctx.defaultCtx( )


logger:info("memory "..collectgarbage("count"))
logger:info("Working ENV Init DONE ... the VM lock will be released ... ")

target = require "script.target"

if not ((target == nil) or (target['onStart'] == nil)) then
    target.onStart()
end

if not ((target == nil) or (target['onPacket'] == nil) or (target['name'] == nil)) then
    pcap.registerSubscriber(target['name'], target['onPacket'])
end

local state = pcap.ModStart()

if "PREPARED" == state then
    pcap.startCap()
end

logger:info( "pcap Mod State:" ..  pcap.getLastError() )

while pcap.getModState() == 'RUNNING'
do
    relaxMachine(1000)
end

if not (target == nil or target['onClose'] == nil) then
    target.onClose()
end

pcap.close()
pcap.exit()