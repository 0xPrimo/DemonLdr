// used by both the Pico Loader and DLL loader
typedef struct {
	__typeof__(LoadLibraryA)   * LoadLibraryA;
	__typeof__(GetProcAddress) * GetProcAddress;
} IMPORTFUNCS;

// used throughout TCG and useful for parsing preplen'd content
typedef struct {
        int   length;
        char  value[];
} _RESOURCE;

// linker intrinsic to map a function hash to a hook registered via Crystal Palace
FARPROC __resolve_hook(DWORD funcHash);

/*
 * Structs used by our DLL loader
 */

#define PTR_OFFSET(x, y) ( (void *)(x) + (ULONG)(y) )
#define DEREF( name )*(UINT_PTR *)(name)

typedef struct {
	IMAGE_DOS_HEADER      * DosHeader;
	IMAGE_NT_HEADERS      * NtHeaders;
	IMAGE_OPTIONAL_HEADER * OptionalHeader;
} DLLDATA;

/*
 * utility functions
 */
DWORD adler32sum(unsigned char * buffer, DWORD length);
DWORD ror13hash(const char * c);

/*
 * printf-style debugging.
 */
void dprintf(char * format, ...);

/*
 * PICO running functions
 */
typedef void (*PICOMAIN_FUNC)(char * arg);

PICOMAIN_FUNC PicoGetExport(char * src, char * base, int tag);
PICOMAIN_FUNC PicoEntryPoint(char * src, char * base);
int PicoCodeSize(char * src);
int PicoDataSize(char * src);
void PicoLoad(IMPORTFUNCS * funcs, char * src, char * dstCode, char * dstData);

/*
 * Resolve functions by walking the export address table
 */
FARPROC findFunctionByHash(HANDLE hModule, DWORD wantedFunctionHash);
HANDLE findModuleByHash(DWORD moduleHash);

/*
 * DLL parsing and loading functions
 */
typedef BOOL WINAPI (*DLLMAIN_FUNC)(HINSTANCE, DWORD, LPVOID);

DLLMAIN_FUNC EntryPoint(DLLDATA * dll, void * base);
IMAGE_DATA_DIRECTORY * GetDataDirectory(DLLDATA * dll, UINT entry);
void LoadDLL(DLLDATA * dll, char * src, char * dst);
void LoadSections(DLLDATA * dll, char * src, char * dst);
void ParseDLL(char * src, DLLDATA * data);
void ProcessImports(IMPORTFUNCS * funcs, DLLDATA * dll, char * dst);
void ProcessRelocations(DLLDATA * dll, char * src, char * dst);
DWORD SizeOfDLL(DLLDATA * data);

/*
 * A macro to figure out our caller
 * https://github.com/rapid7/ReflectiveDLLInjection/blob/81cde88bebaa9fe782391712518903b5923470fb/dll/src/ReflectiveLoader.c#L34C1-L46C1
 */
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif
