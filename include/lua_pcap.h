//
// Created by stubborn on 1/3/17.
//

#ifndef NETWORKMANAGEPLATEFORM_LUA_PCAP_H
#define NETWORKMANAGEPLATEFORM_LUA_PCAP_H

#include <pcap.h>
#include "types.h"
#include "nmp.h"

/**
 * lua_pcap_init
 *
 * @details pcap MoD deinit
 * @param   lua VM state
 *
 * @return  error code ( 0 if no error )
 */

int lua_pcap_init( lua_State *L );

/**
 * lua_pcap_deInit
 *
 * @details pcap MoD deInit
 * @param   null
 *
 * @return  error code ( 0 if no error )
 */

int lua_pcap_deInit( );

#endif //NETWORKMANAGEPLATEFORM_LUA_PCAP_H
