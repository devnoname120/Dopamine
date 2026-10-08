TARGET = systemhook.dylib
CC = clang
SILEO_CONSTRUCTOR_TRACE ?= 0

CFLAGS = -I../.include -I./src -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -install_name $(TARGET) -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -DROOTHIDE_SILEO_CONSTRUCTOR_TRACE=$(SILEO_CONSTRUCTOR_TRACE) -Os -moutline
LDFLAGS = -dynamiclib

SOURCES := $(wildcard src/*.[cSm] src/common/*.[cSm] ../libjailbreak/src/jbclient_*.c ../libjailbreak/src/inline_svc.[cS] ../libjailbreak/src/hookd.c ../_external/modules/litehook/src/*.c ../libjailbreak/src/roothider/jailbreakd.c)
HEADERS := $(shell find src ../.include ../libjailbreak/src ../_external/modules/litehook/src -type f -name '*.h' 2>/dev/null)

sign: $(TARGET)
	@ldid -Cadhoc -S $^

$(TARGET): $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	@rm -f $(TARGET)
