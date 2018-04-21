//
// Created by stubborn on 1/3/17.
//

#include "types.h"
#include "nmp.h"
#include <getopt.h>
#include <cstring>

lua_State   *pMachine = NULL;
pthread_mutex_t Machine_Lock;

static char env_buf[BUFSIZ] = {0};


lua_State *aquireMachine(){
    pthread_mutex_lock(&Machine_Lock);
    return pMachine;
}

int releaseMachine(){
    pthread_mutex_unlock(&Machine_Lock);
    return  0;
}

int lua_relaxMachine(lua_State *L ){

    lua_Integer uSec = luaL_checkinteger( L, -1);

    pthread_mutex_unlock(&Machine_Lock);

    usleep( ( __useconds_t )uSec );

    pthread_mutex_lock(&Machine_Lock);

    return 0;
}

int init() {

    pMachine = luaL_newstate();

    if( NULL == pMachine){
        return EFAULT;
    }

    pthread_mutex_init(&Machine_Lock,NULL);

    luaL_openlibs( pMachine );
    lua_register( pMachine, "relaxMachine", lua_relaxMachine);
    luaopen_pack( pMachine );
    lua_ctx_init( pMachine );
    lua_pcap_init( pMachine );         // Init Pcap Processing Module ...

    return 0;
}

int deInit(){

    lua_ctx_deInit( );
    lua_pcap_deInit( );

    return 0;
}

static int opt_routine( int  argc, char**  argv ){

    int     oc;
    while(  -1 !=( oc = getopt( argc, argv, "s:"))){
        switch(oc){
            case 's':
                if( strlen( optarg ) > 0 ){
                    strcpy( env_buf, optarg );
                    ctxSetString( pMachine ,"script_name", env_buf);
                }
                break;
            default:
                break;
        }
    }
    return  0;
}

int main(int argc, char** argv){

    init();                     // Init the running environment
    opt_routine(argc,argv);

    aquireMachine();
    int ret = luaL_dofile(pMachine,"./script/main/entry.lua"); // Start the main script
    releaseMachine();

    if( ret ){
        printf("Error in script: %s\n",luaL_checkstring(pMachine,-1));
        exit( -1 );
    }

    deInit();

    lua_close( pMachine );
    usleep(500000 );

    return 0;
}
