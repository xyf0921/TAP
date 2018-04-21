--
-- Created by IntelliJ IDEA.
-- User: stubborn
-- Date: 18-4-21
-- Time: 下午2:54
-- To change this template use File | Settings | File Templates.
--

function moveCursor( pointer, bytes )
    local cursor = pcapCurosrMove( pointer, bytes )
    return cursor
end

local function pcapEtherPayloadProtocol( proto_b1,proto_b2)

    if proto_b1 == 0x08 and proto_b2 == 0x00 then
        return "IP"
    elseif proto_b1 == 0x08 and proto_b2 == 0x06 then
        return "ARP"
    else
        return "Unimplemented:"..proto_b1..","..proto_b2
    end
end

local function pcapIpPayloadProtocol( proto_byte )

    if proto_byte == 0x02 then
        return "IGMP"
    elseif proto_byte == 0x06 then
        return "TCP"
    elseif proto_byte == 0x11 then
        return "UDP"
    else
        return "Unimplemented:"..proto_byte
    end
end

local function pcapEthernetHeader( cursor, analyseResult)

    local _, s_b1, s_b2, s_b3, s_b4, s_b5,s_b6 = bunpack( cursor, "bbbbbb", 6)
    cursor = moveCursor( cursor, 6 )
    local _, d_b1, d_b2, d_b3, d_b4, d_b5, d_b6 =bunpack( cursor, "bbbbbb", 6)
    cursor = moveCursor( cursor, 6 )

    local _, proto_b1, proto_b2 = bunpack( cursor, "bb", 2)

    analyseResult['Ethernet.SourceMac'] =
    string.format( "%02X:%02X:%02X:%02X:%02X:%02X", s_b1, s_b2, s_b3, s_b4, s_b5, s_b6 )

    analyseResult['Ethernet.DestinaionMAC'] =
    string.format( "%02X:%02X:%02X:%02X:%02X:%02X", d_b1, d_b2, d_b3, d_b4, d_b5, d_b6 )

    analyseResult['L3Protocol'] = pcapEtherPayloadProtocol( proto_b1, proto_b2)

end

local function pcapIpHeader( cursor, analyseResult)

    local _,b1,b2,TotalLength,ID,S1,TTL,Proto,CSum = bunpack( cursor, "bb>H>H>Hbb>H", 12)

    analyseResult ["IP.Version"]   = bit.rshift( b1, 4)
    analyseResult ["IP.IHL"]       = bit.band( b1, 0x0F)
    analyseResult ["IP.DSCP"]      = bit.rshift( b2, 2)
    analyseResult ["IP.ECN"]       = bit.band( b2, 0x03)
    analyseResult ["IP.Flags"]     = bit.rshift( S1, 13)
    analyseResult ["IP.Frag"]      = bit.band( S1, 0x1F)
    analyseResult ["IP.TotalLength"] = TotalLength
    analyseResult ["IP.ID"]        = ID
    analyseResult ["IP.TTL"]       = TTL
    analyseResult ["IP.Proto"]     = Proto
    analyseResult ["IP.CSum"]      = CSum
    analyseResult ["L4Protocol"]   = pcapIpPayloadProtocol( Proto)

    cursor = moveCursor( cursor, 12 )

    local _, s_b1, s_b2, s_b3, s_b4,
    d_b1, d_b2, d_b3, d_b4 = bunpack( cursor, "bbbbbbbb", 8)

    analyseResult ["IP.Source"] = string.format( "%d.%d.%d.%d", s_b1, s_b2, s_b3, s_b4 )
    analyseResult ["IP.Destination"] = string.format( "%d.%d.%d.%d", d_b1, d_b2, d_b3, d_b4 )

end

local function pcapTCPHeader( cursor, analyseResult)
    local _, s_port, d_port, seq, ack,
    s_1, ws, csum, urg = bunpack( cursor, ">H>H>I>I>H>H>H>H", 20)

    analyseResult ["TCP.SourcePort"]       = s_port
    analyseResult ["TCP.DestinationPort"]  = d_port
    analyseResult ["TCP.Sequence"]         = seq
    analyseResult ["TCP.Ackownlage"]       = ack
    analyseResult ["TCP.IHL"]              = bit.rshift( s_1, 12 )
    analyseResult ["TCP.Flags"]            = bit.band( s_1, 0x00FF )
    analyseResult ["TCP.WindowSize"]       = ws
    analyseResult ["TCP.CheckSum"]         = csum
    analyseResult ["TCP.Urgent"]           = urg

end

local function pcapUDPHeader( cursor, analyseResult)

    local _, s_port, d_port, len, csum = bunpack( cursor, ">H>H>H>H", 8)

    analyseResult ["UDP.SourcePort"]       = s_port
    analyseResult ["UDP.DestinationPort"]  = d_port
    analyseResult ["UDP.Length"]           = len
    analyseResult ["UDP.DataLength"]       = len - 8
    analyseResult ["UDP.CheckSum"]         = csum

end

local function pcapIGMPHeader( _, _)
    -- unimplemented here
end

local function pcapArpHeader( cursor, analyseResult)

    local _,HT,PT,HS,PS,OP = bunpack( cursor, ">H>Hbb>H", 8)

    analyseResult ['ARP.HardwareType'] = HT
    analyseResult ['ARP.ProtocolType'] = PT
    analyseResult['ARP.HarwareSize']   = HS
    analyseResult['ARP.ProtocolSize']  = PS
    analyseResult['ARP.Opcode']        = OP

    cursor = moveCursor( cursor, 8)

    local _, sm_b1, sm_b2, sm_b3, sm_b4,sm_b5, sm_b6,
    s_b1, s_b2, s_b3, s_b4,
    dm_b1, dm_b2, dm_b3, dm_b4, dm_b5, dm_b6,
    d_b1, d_b2, d_b3, d_b4 = bunpack( cursor, "bbbbbbbbbbbbbbbbbbbb", 20)

    analyseResult['ARP.SourceMac'] =
    string.format( "%02X:%02X:%02X:%02X:%02X:%02X", sm_b1, sm_b2, sm_b3, sm_b4, sm_b5, sm_b6 )

    analyseResult['ARP.DestinaionMAC'] =
    string.format( "%02X:%02X:%02X:%02X:%02X:%02X", dm_b1, dm_b2, dm_b3, dm_b4, dm_b5, dm_b6 )

    analyseResult ["ARP.Source"] =
    string.format( "%d.%d.%d.%d", s_b1, s_b2, s_b3, s_b4 )

    analyseResult ["ARP.Destination"] =
    string.format( "%d.%d.%d.%d", d_b1, d_b2, d_b3, d_b4 )

end

local function analysePacket( analyseResult )

    local cursor    = analyseResult['RawPktPointer']
    local len       = analyseResult['PktLen']

    analyseResult['L2Protocol'] = "Ethernet"

    if len >= 14 then

        pcapEthernetHeader( cursor, analyseResult)

        local ethernetDataCursor = moveCursor( cursor, 14 )

        if( "IP"  == analyseResult['L3Protocol'] ) then

            pcapIpHeader( ethernetDataCursor, analyseResult )

            local ipDataCursor = moveCursor( ethernetDataCursor, analyseResult['IP.IHL'] * 4 )

            if ( "TCP" == analyseResult['L4Protocol']) then
                pcapTCPHeader( ipDataCursor, analyseResult )
                analyseResult['L5DataPointer'] = moveCursor( ipDataCursor, analyseResult['TCP.IHL'] * 4 )
            elseif ( "UDP" == analyseResult['L4Protocol']) then
                pcapUDPHeader( ipDataCursor, analyseResult )
                analyseResult['L5DataPointer'] = moveCursor( ipDataCursor, 8 )
            elseif ( "IGMP" == analyseResult['L4Protocol']) then
                pcapIGMPHeader( ipDataCursor, analyseResult )
            end
        elseif( "ARP" == analyseResult['L3Protocol']) then

            pcapArpHeader( ethernetDataCursor, analyseResult )
        end
    end
end

return analysePacket
