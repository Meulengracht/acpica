# Makefile for building the mollenos kernel image
# Includes sub-libraries as
# - acpica
# - arch sub-layer
PROJECT_ROOT := ../../../..
ACPICA_ROOT := ../..
ACPICA_SOURCE := $(ACPICA_ROOT)/source
ACPICA_CORE := $(ACPICA_SOURCE)/components
ACPICA_COMPILER := $(ACPICA_SOURCE)/compiler
ACPICA_OSL := $(ACPICA_SOURCE)/os_specific/service_layers

# Include all the definitions for os
include $(PROJECT_ROOT)/config/common.mk

INCLUDES = -I$(PROJECT_ROOT)/kernel/include -I$(PROJECT_ROOT)/librt/include \
		   -I$(PROJECT_ROOT)/librt/libc/include -I$(PROJECT_ROOT)/librt/libddk/include \
		   -I$(PROJECT_ROOT)/librt/libds/include -I$(ACPICA_SOURCE)/include -I$(ACPICA_COMPILER)

SOURCES_COMMON = $(ACPICA_SOURCE)/common/ahids.c \
				 $(ACPICA_SOURCE)/common/ahuuids.c
SOURCES_DEBUGGER = $(wildcard $(ACPICA_CORE)/debugger/*.c)
SOURCES_DISASM = $(wildcard $(ACPICA_CORE)/disassembler/*.c)
SOURCES_DISPATCH = $(wildcard $(ACPICA_CORE)/dispatcher/*.c)
SOURCES_EVENTS = $(wildcard $(ACPICA_CORE)/events/*.c)
SOURCES_EXECUTER = $(wildcard $(ACPICA_CORE)/executer/*.c)
SOURCES_HARDWARE = $(wildcard $(ACPICA_CORE)/hardware/*.c)
SOURCES_NAMESPACE = $(wildcard $(ACPICA_CORE)/namespace/*.c)
SOURCES_PARSER = $(wildcard $(ACPICA_CORE)/parser/*.c)
SOURCES_RESOURCES = $(wildcard $(ACPICA_CORE)/resources/*.c)
SOURCES_TABLES = $(wildcard $(ACPICA_CORE)/tables/*.c)
SOURCES_UTILITIES = $(wildcard $(ACPICA_CORE)/utilities/*.c)

SOURCES = $(SOURCES_COMMON) $(SOURCES_DEBUGGER) $(SOURCES_DISASM) \
		  $(SOURCES_DISPATCH) $(SOURCES_EVENTS) $(SOURCES_EXECUTER) \
		  $(SOURCES_HARDWARE) $(SOURCES_NAMESPACE) $(SOURCES_PARSER) \
		  $(SOURCES_RESOURCES) $(SOURCES_TABLES) $(SOURCES_UTILITIES) \
		  $(wildcard $(ACPICA_OSL)/osvalik*.c)
OBJECTS = $(SOURCES:.c=.o)

WARNING_FLAGS := -Wno-unused-const-variable
CONFIG_FLAGS := -DACPI_LARGE_NAMESPACE_NODE -DACPI_LIBRARY -DLIBC_KERNEL
CFLAGS = $(GCFLAGS) $(WARNING_FLAGS) $(CONFIG_FLAGS) $(INCLUDES)
LFLAGS = /lib

.PHONY: all
all: $(ACPICA_ROOT)/../build/libacpi.lib

$(ACPICA_ROOT)/../build/libacpi.lib: $(OBJECTS)
	@printf "%b" "\033[0;36mCreating static library " $@ "\033[m\n"
	@$(LD) $(LFLAGS) $(OBJECTS) /out:$@
	
%.o : %.c
	@printf "%b" "\033[0;32m[ACPI] Compiling C source object " $< "\033[m\n"
	@$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	@rm -f $(ACPICA_ROOT)/../build/libacpi.lib
	@rm -f $(OBJECTS)