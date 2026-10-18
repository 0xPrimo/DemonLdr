#include <windows.h>

#include "tcg.h"

WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);

/*
 * This is our opt-in Dynamic Function Resolution resolver. It turns
 * MODULE$Function into pointers. See dfr "resolve" "ror13" "KERNEL32, NTDLL" in
 * loader.spec
 */

FARPROC resolve(DWORD modHash, DWORD funcHash) {
  HANDLE hModule = findModuleByHash(modHash);
  return findFunctionByHash(hModule, funcHash);
}

/*
 * This is our default DFR resolver. It resolves Win32 APIs not handled by
 * another resolver.
 */

FARPROC resolve_ext(char *mod, char *func) {
  HANDLE hModule = KERNEL32$GetModuleHandleA(mod);
  if (hModule == NULL)
    hModule = LoadLibraryA(mod);

  return GetProcAddress(hModule, func);
}

/*
 * This is our opt-in function to help fix ptrs in x86 PIC. See fixptrs _caller"
 * in loader.spec
 */

#ifdef WIN_X86
__declspec(noinline) ULONG_PTR caller(VOID) {
  return (ULONG_PTR)WIN_GET_CALLER();
}
#endif
