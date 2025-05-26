# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)

project(etcs-wireshark VERSION 0.0.1 DESCRIPTION "Wireshark Plugin for European Train Control System" LANGUAGES C)
set(WIRESHARK_PLUGIN_NAME "etcs")

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

add_library(${WIRESHARK_PLUGIN_NAME} MODULE "wireshark-plugin/${WIRESHARK_PLUGIN_NAME}.c")
set_target_properties(${WIRESHARK_PLUGIN_NAME} PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(${WIRESHARK_PLUGIN_NAME} epan)

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS ${WIRESHARK_PLUGIN_NAME}
	LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${WIRESHARK_PLUGIN_NAME}> "${Wireshark_PLUGIN_INSTALL_DIR}/epan"
	COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}/epan"
)

# This custom target installs the plugin to the correct version directory (e.g., "4.4")
# within PLUGIN_CUSTOM_INSTALL_DIR. The idea is that after installing there, we can set
# the environment variable WIRESHARK_PLUGIN_DIR to the same directory, and start Wireshark
# to use the plugin.
set(PLUGIN_VERSION_DIRNAME "${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}")
set(PLUGIN_CUSTOM_INSTALL_DIR "${WIRESHARK_CUSTOM_PLUGIN_DIR}/${PLUGIN_VERSION_DIRNAME}/epan")
add_custom_target(copy_plugin_custom
	COMMAND ${CMAKE_COMMAND} -E make_directory "${PLUGIN_CUSTOM_INSTALL_DIR}"
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${WIRESHARK_PLUGIN_NAME}> "${PLUGIN_CUSTOM_INSTALL_DIR}"
	COMMENT "Installing plugin to: ${PLUGIN_CUSTOM_INSTALL_DIR}"
)
