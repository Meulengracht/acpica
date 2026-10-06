# Project setup
project (vali-lib-acpica)
enable_language (C)

set (SOURCES_COMMON
    source/common/ahids.c
    source/common/ahuuids.c
)

file(GLOB SOURCES_VALI      source/os_specific/service_layers/osvalik*.c)
file(GLOB SOURCES_DEBUGGER  source/components/debugger/*.c)
file(GLOB SOURCES_DISASM    source/components/disassembler/*.c)
file(GLOB SOURCES_DISPATCH  source/components/dispatcher/*.c)
file(GLOB SOURCES_EVENTS    source/components/events/*.c)
file(GLOB SOURCES_EXECUTER  source/components/executer/*.c)
file(GLOB SOURCES_HARDWARE  source/components/hardware/*.c)
file(GLOB SOURCES_NAMESPACE source/components/namespace/*.c)
file(GLOB SOURCES_PARSER    source/components/parser/*.c)
file(GLOB SOURCES_RESOURCES source/components/resources/*.c)
file(GLOB SOURCES_TABLES    source/components/tables/*.c)
file(GLOB SOURCES_UTILITIES source/components/utilities/*.c)

add_library(libacpi
    ${SOURCES_COMMON}
    ${SOURCES_VALI}
    ${SOURCES_DEBUGGER}
    ${SOURCES_DISASM}
    ${SOURCES_DISPATCH}
    ${SOURCES_EVENTS}
    ${SOURCES_EXECUTER}
    ${SOURCES_HARDWARE}
    ${SOURCES_NAMESPACE}
    ${SOURCES_PARSER}
    ${SOURCES_RESOURCES}
    ${SOURCES_TABLES}
    ${SOURCES_UTILITIES}
)
target_compile_options(libacpi PRIVATE $<$<STREQUAL:${VALI_ARCH},aarch64>:-mgeneral-regs-only> $<$<NOT:$<STREQUAL:${VALI_ARCH},aarch64>>:-mno-sse> -Wno-unused-const-variable)
target_compile_definitions(libacpi PRIVATE -DACPI_LARGE_NAMESPACE_NODE -DACPI_LIBRARY -DLIBC_KERNEL -D__LIBDS_KERNEL__)
target_include_directories(libacpi PRIVATE ../libds/include ../../kernel/include ../../boot/include ../libddk/include ../libos/include ../libc/include)
target_include_directories(libacpi PUBLIC source/include)
