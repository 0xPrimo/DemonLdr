#pragma once

#include <windows.h>
#include "tcg.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
#define VirtualAlloc KERNEL32$VirtualAlloc

WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObjectEx( HANDLE hHandle, DWORD dwMilliseconds, WINBOOL bAlertable );
#define WaitForSingleObjectEx KERNEL32$WaitForSingleObjectEx

#ifdef _DEBUG
#define LOG_ERROR( x, ... ) dprintf( "[-] " x "", ##__VA_ARGS__ )
#define LOG_INFO( x, ... ) dprintf( "[*] " x "", ##__VA_ARGS__ )
#define LOG_SUCCESS( x, ... ) dprintf( "[+] " x "", ##__VA_ARGS__ )
#else
#define LOG_ERROR( x, ... )
#define LOG_INFO( x, ... )
#define LOG_SUCCESS( x, ... )
#endif