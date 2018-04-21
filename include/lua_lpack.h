//
// Created by stubborn on 1/10/17.
//

#ifndef NETWORKMANAGEPLATEFORM_LUA_LPACK_H_H
#define NETWORKMANAGEPLATEFORM_LUA_LPACK_H_H

#include <lua.h>
#include <lauxlib.h>

/**
 *
 * Notice :
 *
 *  the lua_string param is replaced with a integer value pointing to the packet data
 *
 *  and please use the cursor to move this pointer
 *
 * */

int luaopen_pack(lua_State *L);


#endif //NETWORKMANAGEPLATEFORM_LUA_LPACK_H_H
