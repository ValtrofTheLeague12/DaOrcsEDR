cmake_minimum_required(VERSION 3.20)

# C is required in addition to CXX: the vendored zstd sources are C.
project(StaticAnalyzer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(STATIC_ANALYZER_STATIC_RUNTIME
    "Statically link the GCC and C++ runtimes"
    ON
)
option(STATIC_ANALYZER_USE_VENDORED_ZSTD
    "Build zstd from the os-libzstd/ source tree instead of using the system library"
    OFF
)
option(STATIC_ANALYZER_LINK_ZSTD
    "Link zstd into static_analyzer itself. Off: nothing in the analyzer needs it."
    OFF
)
option(STATIC_ANALYZER_BUILD_SAMPLE_ARCHIVE
    "Build the sample_archive tool (zstd compress/decompress, for storage or transfer only)"
    ON
)
option(STATIC_ANALYZER_USE_GRAPHVIZ
    "Parse r2 .dot graphs with libgraphviz (cgraph) instead of the dashboard's regex parser"
    ON
)

find_package(LIEF CONFIG REQUIRED
    HINTS "C:/msys64/ucrt64/lib/cmake/LIEF"
)
if(WIN32)
    find_package(re2 CONFIG REQUIRED
        HINTS "C:/msys64/ucrt64/lib/cmake/re2"
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(RE2 REQUIRED IMPORTED_TARGET re2)
    add_library(re2::re2 ALIAS PkgConfig::RE2)
endif()

if(WIN32)
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
    find_path(PDCURSES_INCLUDE_DIR pdcurses.h
        HINTS "C:/msys64/ucrt64/include"
        REQUIRED
    )
    find_library(PDCURSES_LIBRARY NAMES pdcurses
        HINTS "C:/msys64/ucrt64/lib"
        REQUIRED
    )
else()
    find_library(CAPSTONE_STATIC_LIBRARY NAMES capstone REQUIRED)
    find_library(YARA_STATIC_LIBRARY NAMES yara REQUIRED)
    find_library(OPENSSL_CRYPTO_STATIC_LIBRARY NAMES crypto REQUIRED)
    find_library(LIBMAGIC_STATIC_LIBRARY NAMES magic REQUIRED)
    find_package(Curses REQUIRED)
    set(PDCURSES_INCLUDE_DIR "${CURSES_INCLUDE_DIRS}")
    set(PDCURSES_LIBRARY "${CURSES_LIBRARIES}")
endif()

find_path(LIBMAGIC_INCLUDE_DIR magic.h
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)
if(WIN32)
    find_path(TLSH_INCLUDE_DIR tlsh/tlsh.h
        HINTS "C:/msys64/ucrt64/include"
        REQUIRED
    )
else()
    find_path(TLSH_INCLUDE_DIR tlsh.h REQUIRED)
endif()
find_library(TLSH_LIBRARY NAMES tlsh
    HINTS "C:/msys64/ucrt64/lib"
    REQUIRED
)
find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp
    HINTS "C:/msys64/ucrt64/include"
    REQUIRED
)

# yaml-cpp: the pipeline planner reads Jenkins-style YAML configs
# (pipelines/*.yaml). The static archive is preferred on Windows so the exe
# gains no new runtime DLL dependency; other platforms use the CMake package.
if(WIN32)
    find_file(YAML_CPP_STATIC_LIBRARY libyaml-cpp.a
        HINTS "C:/msys64/ucrt64/lib"
        REQUIRED
    )
else()
    find_package(yaml-cpp REQUIRED)
endif()

# ---------------------------------------------------------------------------
# libgraphviz / cgraph (optional)
#
# Used by src/r2/graphviz_parser.cpp to parse the .dot files that r2 emits
# ("agfd" / "agCd"). The dashboard used to parse those with regexes, which
# silently undercounted edges and could not distinguish a node statement from
# an edge attribute block. cgraph is the reference parser.
#
# The Windows Graphviz installer ships MSVC-built .lib files, but cgraph is a
# plain C library with no C++ runtime coupling, and it links and runs correctly
# under the MinGW UCRT64 g++ this project builds with (verified: 50/50 real r2
# .dot files parse, edge counts match an independent ground-truth count).
#
# When cgraph is not found the parser still compiles and reports
# available() == false, and the dashboard keeps using its regex fallback. So
# this is a strict improvement when present and a no-op when absent.
# ---------------------------------------------------------------------------
set(GRAPHVIZ_ENABLED OFF)
if(STATIC_ANALYZER_USE_GRAPHVIZ)
    find_path(GRAPHVIZ_INCLUDE_DIR graphviz/cgraph.h
        HINTS "C:/Program Files/Graphviz/include"
              "C:/msys64/ucrt64/include"
    )
    find_library(GRAPHVIZ_CGRAPH_LIBRARY NAMES cgraph
        HINTS "C:/Program Files/Graphviz/lib"
              "C:/msys64/ucrt64/lib"
    )
    if(GRAPHVIZ_INCLUDE_DIR AND GRAPHVIZ_CGRAPH_LIBRARY)
        set(GRAPHVIZ_ENABLED ON)
        message(STATUS
            "libgraphviz: ${GRAPHVIZ_CGRAPH_LIBRARY} (headers: ${GRAPHVIZ_INCLUDE_DIR})")
    else()
        message(WARNING
            "STATIC_ANALYZER_USE_GRAPHVIZ is ON but cgraph was not found. "
            "The .dot parser will report itself unavailable and the dashboard "
            "will fall back to its regex parser. Install Graphviz or configure "
            "with -DSTATIC_ANALYZER_USE_GRAPHVIZ=OFF to silence this.")
    endif()
endif()

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

if(WIN32)
    add_subdirectory(spdlog)
    set_target_properties(spdlog PROPERTIES POSITION_INDEPENDENT_CODE ON)
else()
    find_package(spdlog CONFIG REQUIRED)
endif()

# ---------------------------------------------------------------------------
# zstd (optional, off by default)
#
# The analyzer used to link a bare "zstd", which was dead weight. Verified with
# `nm --undefined-only libLIEF.a` (1.3 MB of undefined symbols, none matching
# ZSTD_) and `nm --defined-only static_analyzer.exe`, which contains no ZSTD_*
# symbol at all. The only zstd-adjacent names in the binary are
# COMP_zstd_oneshot / ossl_comp_zstd_cleanup, and those come from
# libcrypto.a's c_zstd.obj, which supplies its own implementation. No analyzer
# source includes <zstd.h> either.
#
# So nothing needs zstd and it is not linked. Both switches below exist only so
# the dependency can be restored deliberately if some future code needs it:
#   -DSTATIC_ANALYZER_LINK_ZSTD=ON                    -> link system zstd
#   -DSTATIC_ANALYZER_LINK_ZSTD=ON
#   -DSTATIC_ANALYZER_USE_VENDORED_ZSTD=ON            -> build os-libzstd/ from source
#
# The source list below mirrors upstream lib/libzstd.mk. The program/, tests/,
# contrib/ and zlibWrapper/ trees are deliberately excluded: they contain the
# zstd CLI and test harnesses, not library code.
# ---------------------------------------------------------------------------
# Whether the vendored target is built at all: sample_archive needs it, and the
# analyzer only needs it when explicitly asked to link zstd.
if(STATIC_ANALYZER_USE_VENDORED_ZSTD AND
   (STATIC_ANALYZER_LINK_ZSTD OR STATIC_ANALYZER_BUILD_SAMPLE_ARCHIVE))
    set(ZSTD_DIR "${CMAKE_SOURCE_DIR}/os-libzstd")

    if(NOT EXISTS "${ZSTD_DIR}/lib/zstd.h")
        message(FATAL_ERROR
            "STATIC_ANALYZER_USE_VENDORED_ZSTD is ON but ${ZSTD_DIR}/lib/zstd.h "
            "is missing. Restore the os-libzstd/ checkout, or configure with "
            "-DSTATIC_ANALYZER_USE_VENDORED_ZSTD=OFF to link the system zstd."
        )
    endif()

    # ZSTD_COMMON_FILES + ZSTD_LEGACY_FILES + ZSTD_COMPRESS_FILES
    # + ZSTD_DECOMPRESS_FILES + ZSTD_DEPRECATED_FILES + ZSTD_DICTBUILDER_FILES
    set(ZSTD_SOURCES
        # common
        "${ZSTD_DIR}/lib/common/debug.c"
        "${ZSTD_DIR}/lib/common/entropy_common.c"
        "${ZSTD_DIR}/lib/common/error_private.c"
        "${ZSTD_DIR}/lib/common/fse_decompress.c"
        "${ZSTD_DIR}/lib/common/pool.c"
        "${ZSTD_DIR}/lib/common/threading.c"
        "${ZSTD_DIR}/lib/common/xxhash.c"
        "${ZSTD_DIR}/lib/common/zstd_common.c"
        # compress
        "${ZSTD_DIR}/lib/compress/fse_compress.c"
        "${ZSTD_DIR}/lib/compress/hist.c"
        "${ZSTD_DIR}/lib/compress/huf_compress.c"
        "${ZSTD_DIR}/lib/compress/zstd_compress.c"
        "${ZSTD_DIR}/lib/compress/zstd_compress_literals.c"
        "${ZSTD_DIR}/lib/compress/zstd_compress_sequences.c"
        "${ZSTD_DIR}/lib/compress/zstd_compress_superblock.c"
        "${ZSTD_DIR}/lib/compress/zstd_double_fast.c"
        "${ZSTD_DIR}/lib/compress/zstd_fast.c"
        "${ZSTD_DIR}/lib/compress/zstd_lazy.c"
        "${ZSTD_DIR}/lib/compress/zstd_ldm.c"
        "${ZSTD_DIR}/lib/compress/zstd_opt.c"
        "${ZSTD_DIR}/lib/compress/zstdmt_compress.c"
        "${ZSTD_DIR}/lib/compress/zstd_preSplit.c"
        # decompress
        "${ZSTD_DIR}/lib/decompress/huf_decompress.c"
        "${ZSTD_DIR}/lib/decompress/zstd_ddict.c"
        "${ZSTD_DIR}/lib/decompress/zstd_decompress.c"
        "${ZSTD_DIR}/lib/decompress/zstd_decompress_block.c"
        # Hand-written x86-64 assembly. huf_decompress.c references
        # HUF_decompress4X{1,2}_usingDTable_internal_fast_asm_loop, which live
        # only here - omitting it fails at link with undefined references.
        "${ZSTD_DIR}/lib/decompress/huf_decompress_amd64.S"
        # deprecated (zbuff)
        "${ZSTD_DIR}/lib/deprecated/zbuff_common.c"
        "${ZSTD_DIR}/lib/deprecated/zbuff_compress.c"
        "${ZSTD_DIR}/lib/deprecated/zbuff_decompress.c"
        # dictBuilder
        "${ZSTD_DIR}/lib/dictBuilder/cover.c"
        "${ZSTD_DIR}/lib/dictBuilder/divsufsort.c"
        "${ZSTD_DIR}/lib/dictBuilder/fastcover.c"
        "${ZSTD_DIR}/lib/dictBuilder/zdict.c"
        # legacy (v01..v07, gated internally by ZSTD_LEGACY_SUPPORT)
        "${ZSTD_DIR}/lib/legacy/zstd_v01.c"
        "${ZSTD_DIR}/lib/legacy/zstd_v02.c"
        "${ZSTD_DIR}/lib/legacy/zstd_v03.c"
        "${ZSTD_DIR}/lib/legacy/zstd_v04.c"
        "${ZSTD_DIR}/lib/legacy/zstd_v05.c"
        "${ZSTD_DIR}/lib/legacy/zstd_v06.c"
        "${ZSTD_DIR}/lib/legacy/zstd_v07.c"
    )

    # A deleted file here is a hard generate-time error, which is what we want:
    # silently dropping an object produces undefined-symbol link failures later.
    foreach(_zstd_source IN LISTS ZSTD_SOURCES)
        if(NOT EXISTS "${_zstd_source}")
            message(FATAL_ERROR
                "Vendored zstd source is missing: ${_zstd_source}\n"
                "The os-libzstd/ checkout is incomplete. Restore it with: "
                "git submodule update --init --recursive\n"
            )
        endif()
    endforeach()

    add_library(zstd_vendored STATIC ${ZSTD_SOURCES})
    add_library(StaticAnalyzer::zstd ALIAS zstd_vendored)

    target_include_directories(zstd_vendored PUBLIC "${ZSTD_DIR}/lib")

    # Upstream's own build flags (lib/libzstd.mk):
    #   CPPFLAGS += -DXXH_NAMESPACE=ZSTD_ -DDEBUGLEVEL=0
    #   MinGW:   CPPFLAGS += -D__USE_MINGW_ANSI_STDIO   (%zu formatting)
    # The vendored tree is third-party code built with its own warning policy,
    # so the analyzer's -Wall -Wextra -Wpedantic is deliberately not applied to
    # it; those flags are set on static_analyzer only.
    target_compile_definitions(zstd_vendored PRIVATE
        XXH_NAMESPACE=ZSTD_
        DEBUGLEVEL=0
        ZSTD_LEGACY_SUPPORT=5
    )
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND WIN32)
        target_compile_definitions(zstd_vendored PRIVATE __USE_MINGW_ANSI_STDIO)
    endif()
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(zstd_vendored PRIVATE -O3)
        # Vectorising the sequence decoder costs more than it saves here and
        # upstream disables it too (lib/Makefile: -fno-tree-vectorize).
        set_source_files_properties("${ZSTD_DIR}/lib/decompress/zstd_decompress_block.c"
            PROPERTIES COMPILE_OPTIONS "-fno-tree-vectorize"
        )
    endif()

    # Required so the archive can be absorbed into a shared LIEF build.
    set_target_properties(zstd_vendored PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(STATIC_ANALYZER_LINK_ZSTD)
        set(ZSTD_LINK_TARGET zstd_vendored)
    endif()
endif()

if(STATIC_ANALYZER_LINK_ZSTD)
    if(NOT STATIC_ANALYZER_USE_VENDORED_ZSTD)
        find_library(ZSTD_LIBRARY NAMES zstd libzstd
            HINTS "C:/msys64/ucrt64/lib"
            REQUIRED
        )
        find_path(ZSTD_INCLUDE_DIR zstd.h
            HINTS "C:/msys64/ucrt64/include"
            REQUIRED
        )
        set(ZSTD_LINK_TARGET "${ZSTD_LIBRARY}")
    endif()
else()
    # No ZSTD_LINK_TARGET: static_analyzer's link list omits zstd entirely.
    message(STATUS "zstd: not linked into static_analyzer "
                   "(nothing in the analyzer or its deps requires it)")
endif()

# ---------------------------------------------------------------------------
# sample_archive (optional, on by default)
#
# A standalone zstd compress/decompress tool for sample storage and transfer.
# This is the only thing in the tree that actually needs zstd, and it is a
# separate executable on purpose: sample_archive links zstd, static_analyzer
# does not, and neither one drags the other in.
#
# It resolves zstd the same way the block above does - vendored from
# os-libzstd/ when STATIC_ANALYZER_USE_VENDORED_ZSTD is ON, otherwise the
# MSYS2 library from pacman - so the tool builds either way.
# ---------------------------------------------------------------------------
if(STATIC_ANALYZER_BUILD_SAMPLE_ARCHIVE)
    if(STATIC_ANALYZER_USE_VENDORED_ZSTD)
        # Reuse the target built above rather than declaring it twice.
        if(NOT TARGET zstd_vendored)
            message(FATAL_ERROR
                "sample_archive needs the vendored zstd target, which was not "
                "created. Check STATIC_ANALYZER_LINK_ZSTD / "
                "STATIC_ANALYZER_USE_VENDORED_ZSTD handling above."
            )
        endif()
        set(SAMPLE_ARCHIVE_ZSTD zstd_vendored)
    else()
        find_library(SAMPLE_ARCHIVE_ZSTD_LIBRARY NAMES zstd libzstd
            HINTS "C:/msys64/ucrt64/lib"
            REQUIRED
        )
        find_path(SAMPLE_ARCHIVE_ZSTD_INCLUDE_DIR zstd.h
            HINTS "C:/msys64/ucrt64/include"
            REQUIRED
        )
        set(SAMPLE_ARCHIVE_ZSTD "${SAMPLE_ARCHIVE_ZSTD_LIBRARY}")
    endif()

    # The whole tool lives under tools/sample_archive/ on purpose: the
    # analyzer's source glob is src/*/*.cpp, and anything landing there gets
    # compiled into static_analyzer, which does not link zstd. Three TUs: the
    # CLI driver, the compress/decompress library, and its tiny stderr logger
    # (deliberately not the analyzer's logging subsystem).
    add_executable(sample_archive
        "${CMAKE_SOURCE_DIR}/tools/sample_archive/main.cpp"
        "${CMAKE_SOURCE_DIR}/tools/sample_archive/sample_archive.cpp"
        "${CMAKE_SOURCE_DIR}/tools/sample_archive/archive_log.cpp"
    )
    target_compile_features(sample_archive PRIVATE cxx_std_20)
    target_compile_options(sample_archive PRIVATE
        $<$<CONFIG:Release>:-O2>
        -Wall -Wextra -Wpedantic
    )
    # Project headers (sample_archive/...) first; zstd_vendored exports
    # os-libzstd/lib as a PUBLIC include dir, so the system branch has to
    # supply the zstd include dir explicitly.
    target_include_directories(sample_archive PRIVATE
        "${CMAKE_SOURCE_DIR}/include"
        ${SAMPLE_ARCHIVE_ZSTD_INCLUDE_DIR}
    )
    target_link_libraries(sample_archive PRIVATE ${SAMPLE_ARCHIVE_ZSTD})

    if(STATIC_ANALYZER_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(sample_archive PRIVATE -static-libgcc -static-libstdc++)
    endif()

    message(STATUS "sample_archive: enabled (zstd from "
                   "${SAMPLE_ARCHIVE_ZSTD})")
endif()

# ---------------------------------------------------------------------------
# compressor library (shared, for use by static_analyzer and compressor_tool)
#
# Provides zlib compression with metadata for analysis artifacts.
# ---------------------------------------------------------------------------
add_library(static_analyzer_compressor STATIC
    "${CMAKE_SOURCE_DIR}/src/core/compressor.cpp"
)
target_compile_features(static_analyzer_compressor PRIVATE cxx_std_20)
target_compile_options(static_analyzer_compressor PRIVATE
    $<$<CONFIG:Release>:-O2>
    -Wall -Wextra -Wpedantic
)
target_include_directories(static_analyzer_compressor PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(static_analyzer_compressor PUBLIC
    z
)

if(STATIC_ANALYZER_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(static_analyzer_compressor PRIVATE -static-libgcc -static-libstdc++)
endif()

message(STATUS "compressor library: enabled")

# ---------------------------------------------------------------------------
# compressor_tool (optional, on by default)
#
# A standalone zlib compress/decompress tool with metadata for analysis artifacts.
# Uses the same compressor library as static_analyzer (core/compressor.cpp).
# ---------------------------------------------------------------------------
option(STATIC_ANALYZER_BUILD_COMPRESSOR_TOOL
    "Build the compressor_tool (zlib compress/decompress with metadata)"
    ON
)

if(STATIC_ANALYZER_BUILD_COMPRESSOR_TOOL)
    add_executable(compressor_tool
        "${CMAKE_SOURCE_DIR}/tools/compressor_tool/main.cpp"
        "${CMAKE_SOURCE_DIR}/tools/compressor_tool/compressor_tool.cpp"
    )
    target_compile_features(compressor_tool PRIVATE cxx_std_20)
    target_compile_options(compressor_tool PRIVATE
        $<$<CONFIG:Release>:-O2>
        -Wall -Wextra -Wpedantic
    )
    target_include_directories(compressor_tool PRIVATE
        "${CMAKE_SOURCE_DIR}/include"
    )
    target_link_libraries(compressor_tool PRIVATE
        static_analyzer_compressor
    )

    if(STATIC_ANALYZER_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(compressor_tool PRIVATE -static-libgcc -static-libstdc++)
    endif()

    message(STATUS "compressor_tool: enabled")
endif()

# ---------------------------------------------------------------------------
# dot2json (optional, follows STATIC_ANALYZER_USE_GRAPHVIZ)
#
# A standalone converter that runs the same cgraph parser the analyzer uses to
# turn a directory of r2 .dot files into one normalized graphs.json. The
# dashboard reads that JSON when it is present and falls back to its own regex
# parser when it is not.
#
# It compiles src/r2/graphviz_parser.cpp directly with
# GRAPHVIZ_PARSER_STANDALONE so there is exactly one implementation of the
# parser - the tool and static_analyzer cannot drift apart.
# ---------------------------------------------------------------------------
if(GRAPHVIZ_ENABLED)
    add_executable(dot2json "${CMAKE_SOURCE_DIR}/src/r2/graphviz_parser.cpp")
    target_compile_features(dot2json PRIVATE cxx_std_20)
    target_compile_definitions(dot2json PRIVATE
        STATIC_ANALYZER_USE_GRAPHVIZ
        GRAPHVIZ_PARSER_STANDALONE
    )
    target_compile_options(dot2json PRIVATE
        $<$<CONFIG:Release>:-O2>
        -Wall -Wextra -Wpedantic
    )
    target_include_directories(dot2json PRIVATE
        "${CMAKE_SOURCE_DIR}/include/r2"
        "${GRAPHVIZ_INCLUDE_DIR}"
        "${NLOHMANN_JSON_INCLUDE_DIR}"
    )
    target_link_libraries(dot2json PRIVATE "${GRAPHVIZ_CGRAPH_LIBRARY}")

    if(STATIC_ANALYZER_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(dot2json PRIVATE -static-libgcc -static-libstdc++)
    endif()

    message(STATUS "dot2json: enabled (cgraph from ${GRAPHVIZ_CGRAPH_LIBRARY})")
endif()

# Sources and headers are grouped by module (src/<module>/, include/<module>/),
# so the globs below must recurse.
file(GLOB ANALYZER_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*/*.cpp"
)
# Exclude compressor.cpp since it's built as a separate library
list(FILTER ANALYZER_SOURCES EXCLUDE REGEX ".*/compressor\\.cpp$")
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
install(TARGETS static_analyzer RUNTIME DESTINATION bin)

# Ship the pipeline configs next to the executable: the planner resolves bare
# names (-p extract_strings) against ./pipelines and <exe dir>/pipelines, so
# both the build tree and an install must carry them. The build-tree copy
# mirrors the source directory wholesale; the install rule below filters to
# the data files the planner can read.
add_custom_command(TARGET static_analyzer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/pipelines"
            "$<TARGET_FILE_DIR:static_analyzer>/pipelines"
    COMMENT "Copying pipeline configs next to static_analyzer"
)
install(DIRECTORY "${CMAKE_SOURCE_DIR}/pipelines/"
        DESTINATION bin/pipelines
        FILES_MATCHING
        PATTERN "*.yaml"
        PATTERN "*.yml"
        PATTERN "*.json"
)

add_executable(static_analyzer_cminer
    "${CMAKE_SOURCE_DIR}/tools/cminer/main.cpp"
)
target_compile_features(static_analyzer_cminer PRIVATE cxx_std_20)
target_compile_options(static_analyzer_cminer PRIVATE
    $<$<CONFIG:Release>:-O2>
    -Wall -Wextra -Wpedantic
)
set_target_properties(static_analyzer_cminer PROPERTIES
    OUTPUT_NAME "static-analyzer-cminer"
)
install(TARGETS static_analyzer_cminer RUNTIME DESTINATION bin)

target_compile_options(static_analyzer PRIVATE
    $<$<CONFIG:Release>:-O2>
    -g
    -Wall -Wextra -Wpedantic
)

set_source_files_properties(
    ${CMAKE_SOURCE_DIR}/src/core/trace.cpp
    PROPERTIES COMPILE_OPTIONS "-O2"
)

if(WIN32)
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
endif()

# Every module directory is on the include path, so sources keep using flat
# includes such as #include "yara_scanner.hpp" regardless of where a module
# physically lives. That keeps the reorganisation invisible to the code.
set(ANALYZER_MODULE_DIRS
    core file extract capa yara r2 dig net report ui podman ml_api main
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

if(GRAPHVIZ_ENABLED)
    target_compile_definitions(static_analyzer PRIVATE STATIC_ANALYZER_USE_GRAPHVIZ)
    target_include_directories(static_analyzer PRIVATE "${GRAPHVIZ_INCLUDE_DIR}")
    target_link_libraries(static_analyzer PRIVATE "${GRAPHVIZ_CGRAPH_LIBRARY}")
endif()

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
    ${ZSTD_LINK_TARGET}
    static_analyzer_compressor
)

if(WIN32)
    # libyaml-cpp.a is the static build: without this define the headers mark
    # every symbol dllimport and the linker looks for __imp_ references.
    target_compile_definitions(static_analyzer PRIVATE YAML_CPP_STATIC_DEFINE)
    target_link_libraries(static_analyzer PRIVATE "${YAML_CPP_STATIC_LIBRARY}")
else()
    target_link_libraries(static_analyzer PRIVATE yaml-cpp::yaml-cpp)
endif()

if(WIN32)
    target_link_libraries(static_analyzer PRIVATE
        z
        bz2
        lzma
        gnurx
        ws2_32
        shell32
        dbghelp
        crypt32
        shlwapi
        psapi
        wldap32
    )
else()
    find_package(ZLIB REQUIRED)
    find_package(BZip2 REQUIRED)
    find_package(LibLZMA REQUIRED)
    find_package(Threads REQUIRED)
    target_link_libraries(static_analyzer PRIVATE
        ZLIB::ZLIB
        BZip2::BZip2
        LibLZMA::LibLZMA
        Threads::Threads
    )
endif()

if(WIN32)
    set(STATIC_ANALYZER_MAGIC_DB "C:/msys64/ucrt64/share/misc/magic.mgc")
else()
    set(STATIC_ANALYZER_MAGIC_DB "/usr/share/misc/magic.mgc")
endif()

target_compile_definitions(static_analyzer PRIVATE
    STATIC_ANALYZER_MAGIC_DATABASE="${STATIC_ANALYZER_MAGIC_DB}"
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
