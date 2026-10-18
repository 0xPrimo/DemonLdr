#include "loader.h"

PVOID _VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect ) {
    
    LOG_INFO( "VirtualAlloc is hooked" );
    
    return VirtualAlloc( lpAddress, dwSize, flAllocationType, flProtect );
}

DWORD _WaitForSingleObjectEx( HANDLE hHandle, DWORD dwMilliseconds, WINBOOL bAlertable ) {

    LOG_INFO( "WaitForSingleObjectEx is hooked" );

    return WaitForSingleObjectEx( hHandle, dwMilliseconds, bAlertable );
}
