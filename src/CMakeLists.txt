cmake_minimum_required(VERSION 2.6)

PROJECT(xdp-srv6-remover C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations -D__KERNEL__)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(xdp-srv6-reverser xdp-srv6-reverser.c prog.c net.c map.c)
TARGET_LINK_LIBRARIES(xdp-srv6-reverser bpf nl-tiny)
INSTALL(TARGETS xdp-srv6-reverser
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

add_custom_target(srv6_reverser_kern ALL)
add_custom_command(TARGET srv6_reverser_kern
	COMMAND clang -O2 -target $ENV{BPF_TARGET} -I$ENV{STAGING_DIR}/usr/include/ -I$ENV{STAGING_DIR}/usr/include/bpf/ -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/srv6_reverser_kern.c -o - | llc -march=$ENV{BPF_TARGET} -filetype=obj -o srv6_reverser_kern.o)