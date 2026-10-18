x64:
    load "bin/pico.x64.o"
        make object +disco

    load "bin/hooks.x64.o"
        merge

    mergelib "./libs/libtcg/libtcg.x64.zip"

    # hook demon imports
    addhook "KERNEL32$WaitForSingleObjectEx"    "_WaitForSingleObjectEx"
    
    # demon resolve all its imports with GetProcAddress.
    addhook "KERNEL32$GetProcAddress"           "_GetProcAddress"

    exportfunc "HooksInitialize" "__tag_hooks_initialize"

    export