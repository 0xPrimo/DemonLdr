# DemonLdr

A PoC of User-Defined Reflective Loader for Havoc Framework built with Cystal Palace.

## Setup

**Havoc**:

Clone my fork that support User-Defined Reflective Loader.
```
git clone https://github.com/0xPrimo/Havoc.git
cd Havoc
```

Follow the installation [docs](https://havocframework.com/docs/installation).

**User-Defined Reflective Loader**:


1. Install Crystal Palace linker by following the installation [docs](https://tradecraftgarden.org/docs.html).
2. Start Crystal Palace server:
```sh
cpl server
```
3. Clone repo
```sh
git clone https://github.com/0xPrimo/DemonLdr.git
cd DemonLdr
```

4. Build
```sh
# debug
make x64-debug

# release
make x64
```

4. Load `DemonLdr.py`

## Hooks

**Hook loader imports**:

Edit `loader.spec` :
```
x64:
    ...
    attach "MODULE$FUNC" "_MyHook"
    ...
```

Edit `hooks.c`:
```c
...
BOOL _MyHook() {
    LOG_INFO("_MyHook called");
    return MODULE$FUNC();
}
...
```

**Hook demon imports**:

Edit `pico.spec`:
```
x64:
    ...
    addhook "MODULE$FUNC" "_MyHook"
    ...
```

Edit `hooks.c`:
```c
...
BOOL _MyHook() {
    LOG_INFO("_MyHook called");
    return MODULE$FUNC();
}
...
```