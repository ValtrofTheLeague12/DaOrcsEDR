cmake_minimum_required(VERSION 3.20)

project(StaticAnalyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(STATIC_ANALYZER_STATIC_RUNTIME
    "Statically link the GCC and C++ runtimes"
    ON
)
option(STATIC_ANALYZER_ENABLE_TESTS
    "Build test targets and register CTest tests"
    OFF
)

include(CTest)

find_package(LIEF CONFIG REQUIRED
    HINTS "C:/msys64/ucrt64/lib/cmake/LIEF"
)
find_package(re2 CONFIG REQUIRED
    HINTS "C:/msys64/ucrt64/lib/cmake/re2"
)

find_file(CAPSTONE_STATIC_LIBRARY libcapstone.a
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)
find_file(YARA_STATIC_LIBRARY libyara.a
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)
find_file(OPENSSL_CRYPTO_STATIC_LIBRARY libcrypto.a
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)
find_file(LIBMAGIC_STATIC_LIBRARY libmagic.a
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)

find_path(LIBMAGIC_INCLUDE_DIR magic.h
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)
find_path(TLSH_INCLUDE_DIR tlsh/tlsh.h
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)
find_library(TLSH_LIBRARY NAMES tlsh
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)
find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)
find_path(PDCURSES_INCLUDE_DIR pdcurses.h
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)
find_library(PDCURSES_LIBRARY NAMES pdcurses
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)

find_path(LIBCURL_INCLUDE_DIR curl/curl.h
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)

# NOTE: previously only the curl *headers* were located above. Nothing ever
# resolved or linked the curl *library*, which is why compilation succeeded
# (the compiler only needs the header) but linking failed with
# "undefined reference to __imp_curl_*" (the linker had no library providing
# those symbols). find_library() is used instead of a hardcoded find_file()
# filename because MSYS2/UCRT64 curl typically ships only the shared-library
# import archive (libcurl.dll.a), not a true static libcurl.a.
find_library(LIBCURL_LIBRARY NAMES curl libcurl
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)

add_subdirectory(spdlog)
set_target_properties(spdlog PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Sources and headers are grouped by module (src/<module>/, include/<module>/),
# so the globs below must recurse.
file(GLOB ANALYZER_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*/*.cpp"
)
file(GLOB ANALYZER_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/include/*.h"
    "${CMAKE_SOURCE_DIR}/include/*.hpp"
    "${CMAKE_SOURCE_DIR}/include/*/*.h"
    "${CMAKE_SOURCE_DIR}/include/*/*.hpp"
)

if(NOT ANALYZER_SOURCES)
    message(FATAL_ERROR "No .cpp files found in ${CMAKE_SOURCE_DIR}/src/")
endif()

add_executable(static_analyzer
    ${ANALYZER_SOURCES}
    ${ANALYZER_HEADERS}
)

target_compile_options(static_analyzer PRIVATE
    $<$<CONFIG:Release>:-O2>
    -g
    -Wall -Wextra -Wpedantic
)

set_source_files_properties(
    ${CMAKE_SOURCE_DIR}/src/core/trace.cpp
    PROPERTIES COMPILE_OPTIONS "-O2"
)

set(INSTRUMENTED_FILES
    ${CMAKE_SOURCE_DIR}/src/file/file_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/file/file_hasher.cpp
    ${CMAKE_SOURCE_DIR}/src/extract/extractor.cpp
)
foreach(f ${INSTRUMENTED_FILES})
    if(EXISTS "${f}")
        set_source_files_properties("${f}"
            PROPERTIES COMPILE_OPTIONS "-finstrument-functions")
    endif()
endforeach()

# Every module directory is on the include path, so sources keep using flat
# includes such as #include "yara_scanner.hpp" regardless of where a module
# physically lives. That keeps the reorganisation invisible to the code.
set(ANALYZER_MODULE_DIRS
    core file extract capa yara r2 dig net report ui
)
foreach(module_dir ${ANALYZER_MODULE_DIRS})
    list(APPEND ANALYZER_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/include/${module_dir}")
endforeach()

target_include_directories(static_analyzer PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    ${ANALYZER_INCLUDE_DIRS}
    "${NLOHMANN_JSON_INCLUDE_DIR}"
    "${TLSH_INCLUDE_DIR}"
    "${LIBMAGIC_INCLUDE_DIR}"
    "${LIBCURL_INCLUDE_DIR}"
    "${PDCURSES_INCLUDE_DIR}"
)

target_link_libraries(static_analyzer PRIVATE
    LIEF::LIEF
    re2::re2
    spdlog::spdlog
    "${TLSH_LIBRARY}"
    "${CAPSTONE_STATIC_LIBRARY}"
    "${YARA_STATIC_LIBRARY}"
    "${OPENSSL_CRYPTO_STATIC_LIBRARY}"
    "${LIBMAGIC_STATIC_LIBRARY}"
    "${LIBCURL_LIBRARY}"
    "${PDCURSES_LIBRARY}"
    z
    bz2
    lzma
    zstd
    gnurx
    ws2_32
    shell32
    dbghelp
    crypt32
    shlwapi
    psapi
    wldap32
)

target_compile_definitions(static_analyzer PRIVATE
    STATIC_ANALYZER_MAGIC_DATABASE="C:/msys64/ucrt64/share/misc/magic.mgc"
    STATIC_ANALYZER_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    CTI_WITH_COLLECT
)

if(STATIC_ANALYZER_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(static_analyzer PRIVATE
        -static-libgcc
        -static-libstdc++
    )
endif()

# LIEF's static library (libLIEF.a) already embeds spdlog and fmt objects.
# The vendored spdlog target defines the same symbols, which makes 'ld' fail
# with "multiple definition" errors. Keep the first definition (LIEF's copy)
# and discard the duplicates from the vendored library.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(static_analyzer PRIVATE
        -Wl,--allow-multiple-definition
    )
endif()

# Inert defensive IOC/EICAR fixture. It is deliberately a separate target so
# antivirus scanners and fixture output cannot affect the analyzer executable.
# Test targets are opt-in. Set -DSTATIC_ANALYZER_ENABLE_TESTS=ON to restore
# the test executables and CTest registrations.
if(STATIC_ANALYZER_ENABLE_TESTS)
    add_executable(eicar_ioc_fixture
        "${CMAKE_SOURCE_DIR}/tests/fixtures/eicar_ioc_fixture.cpp"
    )
    target_compile_features(eicar_ioc_fixture PRIVATE cxx_std_20)
    target_compile_options(eicar_ioc_fixture PRIVATE -Wall -Wextra -Wpedantic)

    add_executable(test_ioc
        "${CMAKE_SOURCE_DIR}/tests/test_ioc.c++"
    )
    target_compile_features(test_ioc PRIVATE cxx_std_20)
    target_compile_options(test_ioc PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(STATIC_ANALYZER_ENABLE_TESTS AND BUILD_TESTING)
    add_test(
        NAME test_ioc_generator
        COMMAND test_ioc 10
    )
    set_tests_properties(test_ioc_generator PROPERTIES
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_ioc>"
        TIMEOUT 10
    )

    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    foreach(phase 1 2 3 4)
        add_test(
            NAME test_pe_phase_${phase}
            COMMAND ${Python3_EXECUTABLE}
                    "${CMAKE_SOURCE_DIR}/tests/test_pe_overlay.py"
                    "$<TARGET_FILE:static_analyzer>"
                    "$<TARGET_FILE:eicar_ioc_fixture>"
                    ${phase}
        )
        set_tests_properties(test_pe_phase_${phase} PROPERTIES
            TIMEOUT 150
        )
    endforeach()

    find_program(SMOKE_TEST_BINARY
        NAMES ls.exe true.exe echo.exe pwd.exe
        PATHS "C:/msys64/ucrt64/bin"
        NO_DEFAULT_PATH
    )

    if(NOT SMOKE_TEST_BINARY)
        message(WARNING "No smoke test binary found in C:/msys64/ucrt64/bin")
    else()
        message(STATUS "Smoke test binary: ${SMOKE_TEST_BINARY}")
        add_test(
            NAME static_analyzer_smoke
            COMMAND static_analyzer "${SMOKE_TEST_BINARY}"
        )
        set_tests_properties(static_analyzer_smoke PROPERTIES
            WORKING_DIRECTORY "$<TARGET_FILE_DIR:static_analyzer>"
            TIMEOUT 30
        )
    endif()
endif()
