# Makefile for DarkSword Dopamine Exploit Framework
#
# Builds darksword.framework — Dopamine 2.x exploit plugin (CVE-2025-43520)
# Based on rooootdev/lara real exploit code with 3 bug fixes for iPad8,9
#
# Usage:
#   make                     # Build framework
#   make clean               # Clean build
#   make ipa IPA=Dopamine.ipa  # Build + inject into IPA

# === Configuration ===
SDK           ?= iphoneos
ARCH          ?= arm64e
MIN_IOS       ?= 17.0
FRAMEWORK     := darksword
BUILD_DIR     := build
PRODUCT       := $(BUILD_DIR)/$(FRAMEWORK).framework
ENTITLEMENTS  := Config/lara.entitlements

# Dopamine source root (for libjailbreak headers, optional)
DOPAMINE_SRC  ?= ../Dopamine
LIBJB_HEADERS ?= $(DOPAMINE_SRC)/BaseBin/libjailbreak

# === Toolchain ===
CC            := xcrun -sdk $(SDK) clang
LDFLAGS       := -shared \
                 -framework Foundation \
                 -framework IOKit \
                 -framework IOSurface
CFLAGS        := -arch $(ARCH) \
                 -miphoneos-version-min=$(MIN_IOS) \
                 -isysroot $(shell xcrun --sdk $(SDK) --show-sdk-path 2>/dev/null || echo /dev/null) \
                 -Idarksword \
                 -fobjc-arc \
                 -fvisibility=hidden \
                 -O2 \
                 -DNDEBUG \
                 -Wno-unused-function

# Add Dopamine headers if available
ifneq ($(wildcard $(LIBJB_HEADERS)/primitives_external.h),)
    CFLAGS += -I$(LIBJB_HEADERS) -DHAS_DOPAMINE_HEADERS=1
endif

# === Sources ===
SRCS          := darksword/darksword_exploit.m \
                 darksword/darksword_core.m \
                 darksword/utils.m \
                 darksword/kfs.m \
                 darksword/postexploit.m \
                 darksword/trustcache.m \
                 darksword/bootstrap.m

OBJS          := $(patsubst darksword/%.m,$(BUILD_DIR)/%.o,$(SRCS))

# === Targets ===

.PHONY: all clean install ipa debug

all: $(PRODUCT)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: darksword/%.m | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(PRODUCT): $(OBJS)
	mkdir -p $(PRODUCT)
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-install_name @rpath/$(FRAMEWORK).framework/$(FRAMEWORK) \
		-o $(PRODUCT)/$(FRAMEWORK) \
		$(OBJS)
	cp darksword/Info.plist $(PRODUCT)/Info.plist
	@echo ""
	@echo "=== Build complete ==="
	@echo "Framework: $(PRODUCT)"
	@file $(PRODUCT)/$(FRAMEWORK)

clean:
	rm -rf $(BUILD_DIR)

# Sign with ldid + entitlements (like real lara build)
sign: $(PRODUCT)
	@which ldid >/dev/null 2>&1 || (echo "ERROR: ldid not found"; exit 1)
	ldid -S$(ENTITLEMENTS) $(PRODUCT)/$(FRAMEWORK)
	@echo "Signed with $(ENTITLEMENTS)"

# Install into Dopamine.app
DOPAMINE_APP ?= Dopamine.app
install: $(PRODUCT)
	mkdir -p "$(DOPAMINE_APP)/Frameworks"
	cp -R $(PRODUCT) "$(DOPAMINE_APP)/Frameworks/"
	@echo "Installed to $(DOPAMINE_APP)/Frameworks/$(FRAMEWORK).framework"

# Build + inject into IPA
IPA ?=
ipa: $(PRODUCT)
	@test -n "$(IPA)" || (echo "Usage: make ipa IPA=path/to/Dopamine.ipa"; exit 1)
	@bash build_and_inject.sh "$(IPA)"

# Debug build
debug: CFLAGS += -g -DDEBUG -O0
debug: clean all
info:
	@echo "SDK:            $(SDK)"
	@echo "ARCH:           $(ARCH)"
	@echo "MIN_IOS:        $(MIN_IOS)"
	@echo "DOPAMINE_SRC:   $(DOPAMINE_SRC)"
	@echo "LIBJB_HEADERS:  $(LIBJB_HEADERS)"
	@echo "BUILD_DIR:      $(BUILD_DIR)"
	@echo "PRODUCT:        $(PRODUCT)"
