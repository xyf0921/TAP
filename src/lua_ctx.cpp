//
// Created by stubborn on 1/4/17.
//

#include "lua_ctx.h"

const char *ctxGetString( lua_State *L, const char *key ){

    const char * ret = NULL;

    lua_getglobal( L, "Context");

    lua_pushstring( L, key);
    lua_gettable( L, -2 );

    if( lua_isstring(L , -1) ){
        ret = luaL_checkstring( L, -1 );
    }

    lua_pop( L, 2 );

    return ret;
}

const char *ctxGetStringL( const char *key ){

    const char * ret = NULL;

    lua_State *pMachine = aquireMachine();
    {
        ret = ctxGetString( pMachine, key);
    }
    releaseMachine();

    return ret;
}

lua_Number ctxGetNumber( lua_State *L, const char *key ){

    lua_Number ret = -1 ;

    lua_getglobal( L, "Context");

    lua_pushstring( L, key);
    lua_gettable( L, -2 );

    if( lua_isnumber(L , -1) ){
        ret = luaL_checknumber( L, -1 );
    }

    lua_pop( L, 2 );

    return ret;
}

lua_Number ctxGetNumberL( const char *key ){

    lua_Number ret;

    lua_State *pMachine = aquireMachine();
    {
        ret = ctxGetNumber( pMachine, key);
    }
    releaseMachine();

    return ret;
}

lua_Integer ctxGetInteger( lua_State *L, const char *key ){

    lua_Integer ret = -1 ;

    lua_getglobal( L, "Context" );

    lua_pushstring( L, key );

    lua_gettable( L, -2 );

    if( lua_isinteger( L , -1 ) ){
        ret = luaL_checkinteger( L, -1 );
    }

    lua_pop( L, 2 );

    return ret;
}

lua_Integer ctxGetIntegerL (const char *key){

    lua_Integer ret ;

    lua_State *pMachine = aquireMachine();
    {
        ret = ctxGetInteger( pMachine, key);
    }
    releaseMachine();

    return  ret;
}

int ctxSetString( lua_State *L, const char *key, const char * value){

    lua_getglobal( L, "Context" );

    lua_pushstring( L, key );
    lua_pushstring( L, value);
    lua_settable( L, -3 );
    lua_pop( L, 1 );

    return 0;
}

int ctxSetNumber( lua_State *L, const char *key, lua_Number value){

    lua_getglobal( L, "Context" );

    lua_pushstring( L, key );
    lua_pushnumber( L, value);
    lua_settable( L, -3 );
    lua_pop( L, 1 );

    return 0;
}

int ctxSetInteger( lua_State *L, const char *key, lua_Integer value){

    lua_getglobal( L, "Context" );

    lua_pushstring( L, key );
    lua_pushinteger( L, value);
    lua_settable( L, -3 );
    lua_pop( L, 1 );

    return 0;
}

int ctxSetStringL( const char *key, const char * value){

    lua_State *pMachine = aquireMachine();

    ctxSetString( pMachine, key, value);

    releaseMachine();

    return  0;
}

int ctxSetNumberL( const char *key, lua_Number value){

    lua_State *pMachine = aquireMachine();

    {
        ctxSetNumber( pMachine, key, value);
    }

    releaseMachine();

    return  0;
}

int ctxSetIntegerL( const char *key, lua_Integer value){

    lua_State *pMachine = aquireMachine();

    {
        ctxSetInteger( pMachine, key, value);
    }

    releaseMachine();

    return 0;
}

int lua_ctx_init( lua_State *L){

    lua_newtable( L );
    lua_setglobal(L, "Context");

    return 0;
}

int lua_ctx_deInit( ){

    lua_State *L = aquireMachine();
    {
        lua_newtable( L );
        lua_setglobal(L, "Context");
    }
    releaseMachine();
    return 0;
}