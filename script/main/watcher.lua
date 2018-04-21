local watcherSubscribed = {}

local function connectionWatcher( paramTable )

	local state = paramTable["state_type"]
	local event = paramTable["event_type"]
	local path  = paramTable["path"]

    logger:debug("Connection Watcher triggered event:"..event.."\tstate:"..state)

	for _,v in pairs( watcherSubscribed )
	do
		if ( not( nil == v ) and 'function' == type(v['callback']) ) then
            if( v['event'] == event) then
			    local cb = v['callback']
                cb( state, event, path )
            end
		end
	end
end

local function regiestWatcher( name, event, callback )

	local info = {}

	for _,v in pairs( watcherSubscribed )
	do
		if not( nil == v) and v['name'] == name then
			return -1
		end
	end

	info ['name']  = name
    info ['event'] = event
	info ['callback']  = callback

	table.insert( watcherSubscribed, 1,info )

	return 0
end

local function unregiestWatcher( name )

	for i,v in pairs( watcherSubscribed )
	do
		if not( nil == v) and v['name'] == name then
			table.remove( watcherSubscribed, i )
		end
	end

	return 0
end

----------------------------------------------------------------------------------

local package = {}

package ["connectionWatcher"] 		= connectionWatcher			--	the root Watcher
package ["Register"] 				= regiestWatcher
package ["Unregister"] 				= unregiestWatcher

logger:info("Watcher Mod init finished ... ")

return package
