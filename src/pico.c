#include "loader.h"

FARPROC WINAPI _GetProcAddress( HMODULE hModule, LPCSTR lpProcName ) {
    if ((ULONG_PTR)lpProcName >> 16 == 0) {
        return GetProcAddress( hModule, lpProcName );
    }

    LOG_INFO("Resolving: %s\n", lpProcName );

    FARPROC result = __resolve_hook( ror13hash( lpProcName ) );
    if (result != NULL) {
        return result;
    }

    FARPROC proc = GetProcAddress( hModule, lpProcName );

    return proc;
}

void HooksInitialize( IMPORTFUNCS* funcs ) {
    funcs->GetProcAddress = _GetProcAddress;
}