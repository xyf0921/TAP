//
// Created by stubborn on 1/3/17.
//

#include "types.h"
#include "lua_pcap.h"

#define TIME_OUT_WAIT 0

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

typedef volatile enum PcapState{
    CLOSED = 0,
    PREPARED,
    RUNNING,
    CLOSING,
    ERROR,
    EXIT,
} Mod_State_t;

Mod_State_t Mod_State;

pcap_t *pcap = NULL;

bpf_program bpf;
bpf_u_int32 net = 0,mask = 0;

pthread_t pcapThread;
char lastError [PCAP_ERRBUF_SIZE] = {0};

const char *PcapState2String( volatile enum PcapState Stat){

    switch ( Stat ){
        case CLOSED:
            return "CLOSED";
        case PREPARED:
            return "PREPARED";
        case RUNNING:
            return "RUNNING";
        case CLOSING:
            return "CLOSING";
        case ERROR:
            return "ERROR";
        case EXIT:
            return "EXITING";
        default:
            return "Unkown State";
    }
}

void PcapWatcher( lua_State *pMachine, const char* what ) {

    lua_getglobal(pMachine, "watcher");                  // find the watcher table
    lua_pushstring(pMachine, "connectionWatcher");
    lua_gettable(pMachine, -2);                          // get the ConnectionWatcher function

    lua_newtable(pMachine);                             // push the param table as the function argument
    lua_table_set_string(pMachine, "event_type", what);  // set args
    lua_table_set_string(pMachine, "state_type", PcapState2String( Mod_State));

    if (lua_pcall(pMachine, 1, 0, 0) != LUA_OK) {                   // procedure call
        const char *pc = lua_tostring(pMachine, -1);            // error occurred
        printf("Error in Pcap Watcher C wrap[%s,%d]:%s\n", __FILE__, __LINE__, pc);
    };
    lua_pop(pMachine, 1);   // pop the watcher table

    return;
}

void packet_Handle(u_char *, const struct pcap_pkthdr *pcap_pkthdr,
                             const u_char  *content){

    lua_State *pMachine = aquireMachine();              // get the VM with pMachine locked
    lua_getglobal(pMachine,"pcap");               // find the watcher table
    lua_pushstring(pMachine,"dispatchRoutine");
    lua_gettable(pMachine,-2);                          // get the CompletionRoutine function

    lua_newtable( pMachine );                           // build the param table
    lua_table_set_integer( pMachine, "pcap_len", pcap_pkthdr -> caplen);
    lua_table_set_integer( pMachine, "len", pcap_pkthdr -> len);
    lua_table_set_integer( pMachine, "data", ( lua_Integer ) content );
    lua_table_set_integer( pMachine, "ts_sec", ( lua_Integer ) pcap_pkthdr ->ts.tv_sec );
    lua_table_set_integer( pMachine, "ts_usec", ( lua_Integer ) pcap_pkthdr ->ts.tv_usec );

    if( lua_pcall(pMachine,1,0,0) != LUA_OK){                   // procedure call
        const char * pc = lua_tostring(pMachine,-1);            // error occurred
        printf("Error in Packet Dispatcher C wrap[%s,%d]:%s\n", __FILE__, __LINE__, pc);
    };
    lua_pop( pMachine, 1 );   // pop the completion table
    releaseMachine();       // release lua VM
}

void inline stateSwitchL( volatile enum PcapState stat){

    lua_State *pMachine = aquireMachine();
    {
        Mod_State = stat;
        PcapWatcher( pMachine, "pcapModStateChanged");
    }
    releaseMachine();       // release lua VM
}

void inline stateSwitch(lua_State *L, volatile enum PcapState stat){
    Mod_State = stat;
    PcapWatcher( L, "pcapModStateChanged");
}

static  inline void PcapClose(){
    if( NULL != pcap) {
        pcap_close( pcap );
    }
    pcap = NULL;
}

static inline void OnIdle(){ usleep( 10 ); }

void *pcap_thread( void* ){

    int retCode;
    while( true ){
        switch (Mod_State){
            case RUNNING:{
                if( unlikely( NULL == pcap ) ){
                    sprintf( lastError, "pcap not init");
                    stateSwitchL( ERROR );
                }else{
                    retCode = pcap_dispatch( pcap, 1, &packet_Handle, NULL);
                    if( unlikely( retCode < 0 )){
                        stateSwitchL( ERROR );
                        sprintf( lastError, "pcap processing error:%s",pcap_geterr( pcap ));
                    }
                    else if( unlikely( retCode == 0 ) ){
                        stateSwitchL( CLOSING );
                    }
                }
                continue;
            }
            case CLOSED:
            case ERROR:
            case PREPARED: { OnIdle(); }
                break;
            case CLOSING: {
                PcapClose();
                stateSwitchL( CLOSED );
            }
                break;
            case EXIT:
                return NULL;
        }
    }
    return NULL;
}

static int lua_pcap_open_dev( lua_State *L ){

    const char *dev = luaL_checkstring( L, -2);
    const lua_Integer promisc = luaL_checkinteger( L, -1);

    switch ( Mod_State ){
        case CLOSING:
        case RUNNING:
        case PREPARED: {
            sprintf( lastError, "Already open");
            lua_pushstring( L, lastError);
        }break;
        case EXIT: {
            sprintf( lastError, "Mod pcap Exited (maybe not init yet ...)");
        }break;
        case ERROR: {
            PcapClose();
        };
        case CLOSED:{
            if(pcap_lookupnet( dev, &net, &mask, lastError )) {
                stateSwitch( L, ERROR );
            }
            pcap = pcap_open_live( dev , BUFSIZ, ( int ) promisc, TIME_OUT_WAIT,lastError);
            if( likely( NULL != pcap )){
                stateSwitch( L, PREPARED );
            }else{
                stateSwitch( L, ERROR );
            }
        }break;
    }
    lua_pushstring( L, PcapState2String( Mod_State ));
    return 1;
}

static int lua_pcap_open_file( lua_State *L ){

    const char *fname = luaL_checkstring( L, -1);

    switch ( Mod_State ){
        case CLOSING:
        case RUNNING:
        case PREPARED: {
            sprintf( lastError, "already open");
            lua_pushstring( L, lastError);
        }break;
        case EXIT: {
            sprintf( lastError, "Mod pcap Exited (maybe not init yet ...)");
        }break;
        case ERROR: {
            PcapClose();
        };
        case CLOSED:{
            pcap = pcap_open_offline( fname ,lastError);
            if( unlikely( NULL != pcap )){
                stateSwitch( L, PREPARED );
            }else{
                stateSwitch( L, ERROR );
            }
        }break;
    }
    lua_pushstring( L, PcapState2String( Mod_State ));
    return 1;
}

static int lua_pcap_start( lua_State *L){
    stateSwitch( L, RUNNING );
    lua_pushstring( L, PcapState2String( Mod_State ));

    return 1;
}

static int lua_pcap_close( lua_State *L){
    stateSwitch( L, CLOSING );
    lua_pushstring( L, PcapState2String( Mod_State ));
    return 1;
}

static int lua_pcap_exit( lua_State *L){
    stateSwitch( L, EXIT );
    lua_pushstring( L, PcapState2String( Mod_State ));
    return 1;
}

static int lua_pcap_send( lua_State *L){
    const char *data = luaL_checkstring( L, -2);
    const lua_Integer sz = luaL_checkinteger( L, -1);

    lua_Integer ret = -1;

    if( !( Mod_State == RUNNING || Mod_State == PREPARED )){
        sprintf( lastError, "lua_pacp_send:Device not open");
    }
    else if( (ret = pcap_sendpacket(pcap, ( const u_char *)data, ( int ) sz ) ) ){
            sprintf( lastError, "lua_pacp_send:Packet send failed");
    }

    lua_pushinteger( L, ret);
    return 1;
}

static int lua_pcap_setBPF( lua_State *L){
    const char *BPF = luaL_checkstring( L, -1);

    if( pcap_compile( pcap, &bpf, BPF, 0, net) ){
        sprintf( lastError, "lua_pcap_setBPF: Compile filter failed");
        lua_pushinteger( L, -1 );
    }
    else if( -1 == pcap_setfilter( pcap,&bpf ) ){
        sprintf( lastError, "lua_pcap_setBPF: Set filter failed");
        lua_pushinteger( L, -1 );
    }

    lua_pushinteger( L, 0);
    return 1;
}

static int lua_pcap_getDatalinkInt( lua_State *L){
    int dl;

    if( !( Mod_State == RUNNING || Mod_State == PREPARED )){
        sprintf( lastError, "lua_pcap_datalink: Device not open");
        lua_pushnil( L );
    }
    else{
        dl = pcap_datalink(pcap);
        lua_pushinteger( L, dl );
    }
    return 1;
}

static int lua_pcap_getDatalink( lua_State *L){
    int dl;
    const char * dl_name;

    if( !( Mod_State == RUNNING || Mod_State == PREPARED )){
        sprintf( lastError, "lua_pcap_datalink: Device not open");
        lua_pushnil( L );
    }
    else{
        dl = pcap_datalink(pcap);
        dl_name = pcap_datalink_val_to_name( dl );
        lua_pushstring( L, dl_name );
    }
    return 1;
}

static int lua_pcap_getState( lua_State *L){
    lua_pushstring( L, PcapState2String( Mod_State ) );
    return 1;
}

static int lua_pcap_getError( lua_State *L){
    if( !( Mod_State == RUNNING || Mod_State == PREPARED )){
        lua_pushnil( L );
    }
    else{
        lua_pushstring( L, pcap_geterr( pcap ));
    }
    return 1;
}

static int lua_pcap_lastError( lua_State *L){
    lua_pushstring( L, lastError);
    return 1;
}

static int lua_pcap_Packet_Cursor_Move( lua_State *L){

    const char *pData = ( const char * )luaL_checkinteger( L, -2);
    lua_Integer  size = luaL_checkinteger( L, -1);

    pData += ( size_t )size;
    lua_pushinteger( L, ( lua_Integer )pData);

    return 1;
}

int lua_pcap_init( lua_State *L ){

    sprintf( lastError, "NO ERROR");

    Mod_State = CLOSED;

    lua_register( L, "pcapOpenDev",lua_pcap_open_dev);
    lua_register( L, "pcapOpenFile",lua_pcap_open_file);
    lua_register( L, "pcapStart",lua_pcap_start);
    lua_register( L, "pcapExit",lua_pcap_exit);
    lua_register( L, "pcapClose", lua_pcap_close);
    lua_register( L, "pcapSend", lua_pcap_send);
    lua_register( L, "pcapSetFilter",lua_pcap_setBPF);
    lua_register( L, "pcapDatalinkTypeInt",lua_pcap_getDatalinkInt);
    lua_register( L, "pcapDatalinkType",lua_pcap_getDatalink);
    lua_register( L, "pcapGetState",lua_pcap_getState);
    lua_register( L, "pcapGetError",lua_pcap_getError);
    lua_register( L, "pcapLastError",lua_pcap_lastError);
    lua_register( L, "pcapCurosrMove",lua_pcap_Packet_Cursor_Move);

    pthread_create( &pcapThread, 0, &pcap_thread, NULL);
    return 0;
}

int lua_pcap_deInit( ){
    Mod_State = EXIT;
    pthread_join( pcapThread, NULL );
    return 0;
}