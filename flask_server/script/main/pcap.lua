
local pcapCallback	= {}
local analysePacket	= require "script.main.analyse"

local function openDevice( devName, promisc)
    local state = pcapOpenDev( devName, promisc)
    return state;
end

local function openFile( fname )
    local state = pcapOpenFile( fname )
    return state;
end

local function startCapture( )
    local state = pcapStart( )
    return state;
end

local function close( )

    local retCode = pcapClose( )
    return retCode;
end

local function sendPacket( data, size)
    local bytes = pcapSend( data, size )
    return bytes;
end

local function setFilter( bpf )
    local retCode = pcapSetFilter( bpf )
    return retCode;
end

local function getDataLinkTypeInt()
    local dl = pcapDatalinkTypeInt( )
    return dl;
end

local function getDataLinkType()
    local dl = pcapDatalinkType( )
    return dl;
end

local function getModState()
    local dl = pcapGetState()
    return dl;
end

local function getPcapError( )
    local err = pcapGetError( )
    return err;
end

local function getLastError( )
    local err = pcapLastError( )
    return err;
end

local function exit( )
    local err = pcapExit( )
    return err;
end

local function dispatchRoutine( paramTable )

    local analyseResult = {}

    analyseResult['RawPktPointer'] = paramTable['data']
    analyseResult['PktLen']        = paramTable['len']
    analyseResult['PktPcapLen']    = paramTable['pcap_len']
    analyseResult['PktTs_sec']     = paramTable['ts_sec']
    analyseResult['PktTs_us']      = paramTable['ts_usec']

    analysePacket( analyseResult )

    local cb

    for _,v in pairs( pcapCallback )
    do
        if ( not( nil == v ) and ( 'function' == type(v['callback']) ) ) then
            cb = v['callback']
            cb( paramTable, analyseResult )
        end
    end
end

local function registerSubscriber( name, callback )

    local info = {}

    info ['name']  = name
    info ['callback']   = callback

    for _,v in pairs( pcapCallback )
    do
        if not( nil == v) and v['name'] == name then
            return
        end
    end

    table.insert( pcapCallback, 1,info )
    return
end

local function unregisterSubscriber( name )

    for i,v in pairs( pcapCallback )
    do
        if not( nil == v) and v['name'] == name then
            table.remove( pcapCallback, i )
        end
    end
    return
end

local function pcapModStart()

    local source    = ctx.get	("pcap.source")
    local device    = ctx.get	("pcap.device")
    local filePath  = ctx.get	("pcap.filePath")
    local ret,error,state

    local promisc   = ctx.get	("pcap.promisc")
    if source == "device" then
        ret = pcap.openDevice( device, promisc )
    elseif source == "file" then
        ret = pcap.openFile( filePath )
    end
    error = pcap.getLastError()
    state = pcap.getModState()

    logger:info("pcap Mod errorBuffer:"..error)
    logger:info("the current state is:"..state)

    return state
end

package ['openDevice']  = openDevice
package ['openFile']    = openFile

package ['sendPacket']  = sendPacket
package ['setFilter']   = setFilter

package ['getDataLinkType'] = getDataLinkType
package ['getDataLinkTypeInt'] = getDataLinkTypeInt
package ['getModState']     = getModState

package ['getPcapError']    = getPcapError
package ['getLastError']    = getLastError

package ['dispatchRoutine'] = dispatchRoutine
package ['registerSubscriber'] = registerSubscriber
package ['unregisterSubscriber'] = unregisterSubscriber

package ['analysePacket'] = analysePacket
package ['pcapCurosrMove'] = moveCursor

package ['close']       = close
package ['startCap']    = startCapture
package ['ModStart'] = pcapModStart
package ['exit']        = exit

return package
