--  上下文设置:
--            pcap.source: 数据源,可以是device或者file
--            pcap.filePath: 文件名
--            pcap.device:设备名
--            pcap.promisc:是否开启混杂模式
--
--            onStart: 在解析前执行
--            onPacket: 每个数据包执行
--            onClose: 结束前执行
--    现成的解析结果:
--    analyseResult 包含键值:
--              RawPktPointer: 生数据游标
--              PktLen: 数据包长度
--              PktTs_sec: 抓取时间(ms)
--              PktTs_us: 抓取时间(us)
--              ETH, IP, UDP, TCP, ICMP协议的解析结果
--    自主解析接口:
--          ret_cursor = moveCursor(cursor, bytes):
--              移动数据游标,将 cursor 移动 bytes字节返回到 ret_cursor中
--          unpack_len, obj1, obj2, ... = bunpack(cursor, format, bytes):
--              从cursor处解析format格式的数据,返回结果
--          obj = bpack(format, param1, param2, ...):
--              将param中的参数写入二进制buf中,装入obj对象中
--    其他API接口参考文档

ctx.set("pcap.source", "file")
ctx.set("pcap.filePath", "./test.pcap")

local count

local function onStart()
    print('PacketCounter started')
    count = 0
end

local function onClose()
    print('PacketCounter finished\npacket count:'..count)
end

local function onPacket( _ , analyseResult)
    cursor = analyseResult['RawPktPointer']
    cursor = moveCursor(cursor, 1)
    count = count + 1
end

package={}
package['name']="PacketCounter"
package['onStart']=onStart
package['onClose']=onClose
package['onPacket']=onPacket

return package