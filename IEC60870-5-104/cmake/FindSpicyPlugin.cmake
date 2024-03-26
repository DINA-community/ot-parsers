# Find the Spicy plugin to get access to the infrastructure it provides.
#
# While most of the actual CMake logic for building analyzers comes with the Spicy
# plugin for Zeek, this code bootstraps us by asking "spicyz" for the plugin's
# location. Either make sure that "spicyz" is in PATH, set the environment
# variable SPICYZ to point to its location, or set variable ZEEK_SPICY_ROOT
# in either CMake or environment to point to its installation or build
# directory.
#
# This exports:
#
#     SPICY_PLUGIN_FOUND            True if plugin and all dependencies were found
#     SPICYZ                        Path to spicyz
#     SPICY_PLUGIN_VERSION          Version string of plugin
#     SPICY_PLUGIN_VERSION_NUMBER   Numerical version number of plugin

# Runs `spicyz` with the flags given as second argument and stores the output in the variable named
# by the first argument.
function (run_spicycz output)
    execute_process(COMMAND "${SPICYZ}" ${ARGN} OUTPUT_VARIABLE output_
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    string(STRIP "${output_}" output_)
    set(${output} "${output_}" PARENT_SCOPE)
endfunction ()

# Checks that the Spicy plugin version it at least the given version.
function (spicy_plugin_require_version version)
    string(REGEX MATCH "([0-9]*)\.([0-9]*)\.([0-9]*).*" _ ${version})
    math(EXPR version_number "${CMAKE_MATCH_1} * 10000 + ${CMAKE_MATCH_2} * 100 + ${CMAKE_MATCH_3}")

    if ("${SPICY_PLUGIN_VERSION_NUMBER}" LESS "${version_number}")
        message(FATAL_ERROR "Package requires at least Spicy plugin version ${version}, "
                            "have ${SPICY_PLUGIN_VERSION}")
    endif ()
endfunction ()

###
### Main
###

if (NOT SPICYZ)
    set(SPICYZ "$ENV{SPICYZ}")
endif ()

if (NOT SPICYZ)
    # Support an in-tree Spicy build.
    find_program(
        spicyz spicyz
        HINTS ${ZEEK_SPICY_ROOT}/bin ${ZEEK_SPICY_ROOT}/build/bin $ENV{ZEEK_SPICY_ROOT}/bin
              $ENV{ZEEK_SPICY_ROOT}/build/bin ${PROJECT_SOURCE_DIR}/../../build/bin)
    set(SPICYZ "${spicyz}")
endif ()

message(STATUS "spicyz: ${SPICYZ}")

if (SPICYZ)
    set(SPICYZ "${SPICYZ}" CACHE PATH "" FORCE) # make sure it's in the cache

    run_spicycz(SPICY_PLUGIN_VERSION "--version")
    run_spicycz(SPICY_PLUGIN_VERSION_NUMBER "--version-number")
    message(STATUS "Zeek plugin version: ${SPICY_PLUGIN_VERSION}")

    run_spicycz(spicy_plugin_path "--print-plugin-path")
    set(spicy_plugin_cmake_path "${spicy_plugin_path}/cmake")
    message(STATUS "Zeek plugin CMake path: ${spicy_plugin_cmake_path}")

    list(PREPEND CMAKE_MODULE_PATH "${spicy_plugin_cmake_path}")
    find_package(Zeek REQUIRED)
    find_package(Spicy REQUIRED)
    zeek_print_summary()
    spicy_print_summary()

    include(ZeekSpicyAnalyzerSupport)
endif ()

#Fetch none tested zeek versions resulting in build errors
if (ZEEK_VERISON VERSION_GREATER "6.0.3")
    message(NOTICE "Zeek versions greater than 6.0.3 are not tested and might fail to compile the parser successfully")

    #stop iminent reported crash related to specific versions
    if (ZEEK_VERISON VERSION_EQUAL "6.1.1")
    message (NOTICE "Zeek version 6.1.1 is reported to fail to compile the parser. Please use a different version (E.g. 6.0.3)."
    message (FATAL_ERROR "Spotted incompatible Zeek version - aborting")
    endif
endif

#Fetch none tested spicy versions resulting in build errors
if (SPICY_PLUGIN_VERSION VERSION_GREATER "1.8.1")
    message(NOTICE "Spicy versions greater than 1.8.1 might fail to compile the parser successfully")

    #stop iminent reported crash related to specific versions
    if (SPICY_PLUGIN_VERSION VERSION_EQUAL "1.9.0")
        message (NOTICE "Spicy version 1.9.0 is reported to fail to compile the parser. Please use a different version (E.g. 1.8.1)"
        message (FATAL_ERROR "Spotted incompatible Spicy version - aborting")
    endif
endif

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SpicyPlugin DEFAULT_MSG SPICYZ ZEEK_FOUND)
