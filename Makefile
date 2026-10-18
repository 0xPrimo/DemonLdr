CYRSTAL_LINKER	= cpl link
CC_64			= x86_64-w64-mingw32-gcc
CFLAGS			= -O1 -fno-jump-tables -shared -Wall -Wno-pointer-arith

.PHONY: all x64 clean

all: x64

bin:
	mkdir -p bin

libtcg:
	@make x64 -C libs/libtcg

x64: bin libtcg
	@echo "[*] Compiling..."
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/loader.c -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/hooks.c -o bin/hooks.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/pico.c -o bin/pico.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/services.c -o bin/services.x64.o

x64-debug: bin libtcg
	@echo "[*] Compiling..."
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/loader.c -D _DEBUG -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/hooks.c -D _DEBUG -o bin/hooks.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/pico.c -D _DEBUG -o bin/pico.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -Iinclude -c src/services.c -D _DEBUG -o bin/services.x64.o

clean:
	rm -rf bin
	@make clean -C libs/libtcg
