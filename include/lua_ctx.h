//
// Created by stubborn on 1/4/17.
//

#ifndef NETWORKMANAGEPLATEFORM_LUA_CONTEXT_H
#define NETWORKMANAGEPLATEFORM_LUA_CONTEXT_H

#include "types.h"
#include "nmp.h"

/**
 * @name ctxGetString
 *
 * @details get a string from the current context ( without locking VM)
 * @param
        *      lua_State L
        *      const char * key
 * @return  pointer to the string ( NULL if not exist)
 */
const char *ctxGetString( lua_State *L, const char *key );

/**
 * @name ctxGetNumber
 *
 * @details get a Number from the current context ( without locking VM)
 * @param
        *      lua_State L
        *      const char * key
 * @return  the number ( -1 if not exist )
 */

lua_Number ctxGetNumber( lua_State *L, const char *key );

/**
 * @name ctxGetInteger
 *
 * @details get a Integer from the current context ( without locking VM)
 * @param
        *      lua_State L
        *      const char * key
 * @return  the integer ( -1 if not exist )
 */

lua_Integer ctxGetInteger( lua_State *L, const char *key );

/**
 * @name ctxGetStringL
 *
 * @details lock the VM and get a String from the current context
 * @param
        *      lua_State L
        *      const char * key
 * @return  pointer to the string ( NULL if not exist )
 */

const char *ctxGetStringL( const char *key );

/**
 * @name ctxGetNumberL
 *
 * @details lock the VM and get a Number from the current context
 * @param
        *      lua_State L
        *      const char * key
 * @return  the number ( -1 if not exist )
 */

lua_Number ctxGetNumberL( const char *key );

/**
 * @name ctxGetIntegerL
 *
 * @details lock the VM and get a Integer from the current context
 * @param
        *      lua_State L
        *      const char * key
 * @return  the integer ( -1 if not exist )
 */

lua_Integer ctxGetIntegerL(const char *key );

/**
 * @name ctxSetString
 *
 * @details set a String to the current context
 * @param
        *      lua_State L
        *      const char * key
        *      const char * value
 * @return  0
 */

int ctxSetString( lua_State *L, const char *key, const char * value);

/**
 * @name ctxSetNumber
 *
 * @details set a Number to the current context ( without locking VM )
 * @param
        *      lua_State L
        *      const char * key
        *      lua_Number value
 * @return  0
 *
 */

int ctxSetNumber( lua_State *L, const char *key, lua_Number value);

/**
 * @name ctxSetInteger
 *
 * @details set a Integer to the current context ( without locking VM )
 * @param
        *      lua_State L
        *      const char * key
        *      lua_Integer value
 * @return  0
 *
 */

int ctxSetInteger( lua_State *L, const char *key, lua_Integer value);

/**
* @name ctxSetStringL
*
* @details lock the VM and set a String to the current context
* @param
        *      lua_State L
        *      const char * key
        *      const char * value
        * @return  0
*
*/

int ctxSetStringL( const char *key, const char * value);

/**
* @name ctxSetNumberL
*
* @details lock the VM and set a Number to the current context
* @param
        *      lua_State L
        *      const char * key
        *      lua_Number value
* @return  0
*
*/

int ctxSetNumberL( const char *key, lua_Number value);

/**
* @name ctxSetIntegerL
*
* @details lock the VM and set a Integer to the current context
* @param
        *      lua_State L
        *      const char * key
        *      lua_Integer value
* @return  0
*
*/

int ctxSetIntegerL( const char *key, lua_Integer value);

/**
* @name lua_ctx_init
*
* @details init the ctx for the lua VM
* @param
        *      lua_State L
        *
* @return  0
*
*/

int lua_ctx_init( lua_State *L);

/**
* @name lua_ctx_deinit
*
* @details deinit the ctx for the lua VM
* @param    null
* @return  0
*
*/

int lua_ctx_deInit( );

inline int lua_table_set_integer( lua_State *L, const char *key, lua_Integer value){

    lua_pushstring( L, key);
    lua_pushinteger( L, value);
    lua_settable( L, -3);

    return 0;
}

UNUSE_DONT_WARNING  inline int lua_table_set_number( lua_State *L, const char *key, lua_Number value){
    lua_pushstring( L, key);
    lua_pushnumber( L, value);
    lua_settable( L, -3);

    return 0;
}

inline int lua_table_set_string( lua_State *L, const char *key, const char *value){

    lua_pushstring( L, key);
    lua_pushstring( L, value);
    lua_settable( L, -3);

    return 0;
}

inline int lua_table_set_string_idx( lua_State *L, int key, const char *value){

    lua_pushinteger( L, key);
    lua_pushstring( L, value);
    lua_settable( L, -3);

    return 0;
}

inline const char *lua_table_get_string( lua_State *L, const char *key){

    const char *ret;

    lua_pushstring( L, key);
    lua_gettable( L, -2);

    ret = luaL_checkstring( L, -1);

    lua_pop( L , 1 );

    return ret;
}

inline const lua_Integer lua_table_get_int( lua_State *L, const char *key){
    lua_Integer  ret;

    lua_pushstring( L, key);
    lua_gettable( L, -2);

    ret = luaL_checkinteger( L, -1);

    lua_pop( L , 1 );

    return ret;
}

#endif //NETWORKMANAGEPLATEFORM_LUA_CONTEXT_H
