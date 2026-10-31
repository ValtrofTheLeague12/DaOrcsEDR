cmake_minimum_required(VERSION 3.20)

# C is required in addition to CXX: the vendored zstd sources are C.
project(StaticAnalyzer VERSION 1.0.0 LANGUAGES C CXX)

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
option(STATIC_ANALYZER_USE_MEGA_SDK
    "Link the MEGA cloud SDK (MEGA::SDKlib) for evidence storage. Requires an MSVC v142+ toolset, a Windows SDK, Crypto++, libsodium and ICU; it cannot build with the MinGW/UCRT64 compiler this project otherwise uses."
    OFF
)

# ---------------------------------------------------------------------------
# Windows binary hardening.
#
# Four protections, each ON by default because MinGW's linker already turns
# the first three on and the compiler already supports the fourth. The point
# of the options is that the INTENT is recorded: build-ucrt/CMakeCache.txt then
# says which protections this tree was configured for, and the panel compares
# that against what the finished PE header actually carries.
#
# The settings live in config/hardening.json, which build.ps1 reads and the
# panel writes, so a build started from the panel and a build started from a
# terminal produce the same binary. See python/panel/hardening.py.
# ---------------------------------------------------------------------------
option(STATIC_ANALYZER_HARDENING_ASLR
    "Relocate the image at load time (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)"
    ON
)
option(STATIC_ANALYZER_HARDENING_HIGH_ENTROPY_VA
    "Relocate across the full 64-bit address space (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)"
    ON
)
option(STATIC_ANALYZER_HARDENING_DEP_NX
    "Mark the stack and heap non-executable (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)"
    ON
)
option(STATIC_ANALYZER_HARDENING_STACK_PROTECTOR
    "Check a canary on every protected stack frame (-fstack-protector-strong)"
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

# Ship the MinGW runtime next to the executable.
#
# This is not tidiness, it is the difference between the binary running and not
# running. The loader searches the executable's own directory BEFORE PATH, so
# placing the DLLs here makes the binary immune to a same-named DLL sitting
# earlier on PATH - and that is not hypothetical here. Graphviz installs its own
# zlib1.dll into "C:\Program Files\Graphviz\bin", that directory comes before
# msys64 on a default Windows PATH, and the loader picked Graphviz's zlib rather
# than the one this executable links against. The symptom was a silent failure
# to start: exit code 0xC0000139 (STATUS_ENTRYPOINT_NOT_FOUND) with no output
# whatsoever, which reads like a broken build rather than a PATH collision.
get_filename_component(_ucrt_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)

# The transitive closure of the executable's imports, by source directory. An
# explicit list rather than a wildcard on purpose: msys64's bin holds hundreds
# of DLLs, many alternate versions of each other, and copying all of it beside
# the executable would make the shadowing problem worse instead of better. The
# closure is walked, not guessed - a DLL that is merely named on PATH can still
# fail to load if it is the wrong build. Regenerate with tools/dll_closure.py.
set(_runtime_dlls_ucrt
    libsystre-0.dll          # Rust support library, pulled in by trace.cpp
    libtre-5.dll             # ... which needs it in turn
    libwinpthread-1.dll
    libgcc_s_seh-1.dll
    libstdc++-6.dll
    zlib1.dll
    # libcurl's closure
    libcurl-4.dll
    libbrotlidec.dll
    libcrypto-3-x64.dll
    libidn2-0.dll
    libnghttp2-14.dll
    libnghttp3-9.dll
    libngtcp2-16.dll
    libngtcp2_crypto_ossl-0.dll
    libpsl-5.dll
    libssh2-1.dll
    libssl-3-x64.dll
    libzstd.dll
    # libre2's closure (absl)
    libre2-11.dll
    libabsl_hash-2508.0.0.dll
    libabsl_log_internal_message-2508.0.0.dll
    libabsl_raw_hash_set-2508.0.0.dll
    libabsl_spinlock_wait-2508.0.0.dll
    libabsl_str_format_internal-2508.0.0.dll
    libabsl_strings-2508.0.0.dll
    libabsl_synchronization-2508.0.0.dll
    # PDCurses
    libpdcurses.dll
)
set(_runtime_dlls_graphviz
    cgraph.dll
    cdt.dll
)

set(_copy_runtime_commands)
foreach(_dll IN LISTS _runtime_dlls_ucrt)
    # Copied only if it exists, so a machine missing one still builds.
    if(_ucrt_bin AND EXISTS "${_ucrt_bin}/${_dll}")
        list(APPEND _copy_runtime_commands
             COMMAND ${CMAKE_COMMAND} -E copy_if_different
                     "${_ucrt_bin}/${_dll}"
                     "$<TARGET_FILE_DIR:static_analyzer>/${_dll}")
    endif()
endforeach()
foreach(_dll IN LISTS _runtime_dlls_graphviz)
    if(GRAPHVIZ_CGRAPH_LIBRARY)
        get_filename_component(_graphviz_libdir "${GRAPHVIZ_CGRAPH_LIBRARY}" DIRECTORY)
        # .../<root>/bin/cgraph.dll sits beside .../<root>/lib/cgraph.lib
        get_filename_component(_graphviz_bin "${_graphviz_libdir}/../bin" ABSOLUTE)
        if(EXISTS "${_graphviz_bin}/${_dll}")
            list(APPEND _copy_runtime_commands
                 COMMAND ${CMAKE_COMMAND} -E copy_if_different
                         "${_graphviz_bin}/${_dll}"
                         "$<TARGET_FILE_DIR:static_analyzer>/${_dll}")
        endif()
    endif()
endforeach()

# Ship pipeline and artifact configuration, plus the uploader's runtime
# modules, beside the executable. This keeps named pipelines and opt-in bundle
# actions available when launched outside the source tree.
add_custom_command(TARGET static_analyzer POST_BUILD
    ${_copy_runtime_commands}
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/pipelines"
            "$<TARGET_FILE_DIR:static_analyzer>/pipelines"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:static_analyzer>/config"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/config/artifacts.yaml"
            "$<TARGET_FILE_DIR:static_analyzer>/config/artifacts.yaml"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:static_analyzer>/mega"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/mega/upload.py"
            "$<TARGET_FILE_DIR:static_analyzer>/mega/upload.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/mega/megacmd.py"
            "$<TARGET_FILE_DIR:static_analyzer>/mega/megacmd.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/mega/credential.py"
            "$<TARGET_FILE_DIR:static_analyzer>/mega/credential.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/mega/seal.py"
            "$<TARGET_FILE_DIR:static_analyzer>/mega/seal.py"
    COMMENT "Copying runtime DLLs, pipeline and config next to static_analyzer"
)
# The copies above ride on the exe link, so make has no reason to re-run them
# when only a YAML file changed - and that is exactly the common case, because
# the Analysis Configuration page edits pipelines/*.yaml in place without
# touching a source file. The result was a copy beside the executable that
# served stale settings to anyone launching the analyzer from outside the tree.
# This target runs on every build for that reason, and depends on the directory
# so an edit re-triggers it.
file(GLOB_RECURSE _pipeline_sidecar_deps CONFIGURE_DEPENDS
     "${CMAKE_SOURCE_DIR}/pipelines/*")
add_custom_target(static_analyzer_sidecar ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/pipelines"
            "$<TARGET_FILE_DIR:static_analyzer>/pipelines"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/config/artifacts.yaml"
            "$<TARGET_FILE_DIR:static_analyzer>/config/artifacts.yaml"
    DEPENDS ${_pipeline_sidecar_deps}
    COMMENT "Refreshing pipelines/ and config/ next to static_analyzer"
)
add_dependencies(static_analyzer_sidecar static_analyzer)
install(DIRECTORY "${CMAKE_SOURCE_DIR}/pipelines/"
        DESTINATION bin/pipelines
        FILES_MATCHING
        PATTERN "*.yaml"
        PATTERN "*.yml"
        PATTERN "*.json"
)
install(FILES "${CMAKE_SOURCE_DIR}/config/artifacts.yaml"
        DESTINATION bin/config)
install(FILES
        "${CMAKE_SOURCE_DIR}/mega/upload.py"
        "${CMAKE_SOURCE_DIR}/mega/megacmd.py"
        "${CMAKE_SOURCE_DIR}/mega/credential.py"
        DESTINATION bin/mega)

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

# ---------------------------------------------------------------------------
# Windows binary hardening, applied to the analyzer.
#
# The three PE-header protections are LINK flags: they set the
# IMAGE_DLLCHARACTERISTICS_* bits that Windows itself reads. The enable forms
# are written out explicitly even though the MinGW specs already default them
# on, because "the toolchain defaults to it" is not the same claim as "this
# build asked for it" - and a build that quietly loses a protection because a
# toolchain changed its default is exactly what the settings file exists to
# prevent.
#
# The stack protector is a COMPILE flag and leaves no header bit behind. It is
# detected in the finished binary by the canary runtime being linked in, which
# is a weaker signal than the other three and is reported as such.
# ---------------------------------------------------------------------------
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(STATIC_ANALYZER_HARDENING_ASLR)
        target_link_options(static_analyzer PRIVATE -Wl,--dynamicbase)
    else()
        target_link_options(static_analyzer PRIVATE -Wl,--disable-dynamicbase)
    endif()

    if(STATIC_ANALYZER_HARDENING_HIGH_ENTROPY_VA)
        target_link_options(static_analyzer PRIVATE -Wl,--high-entropy-va)
    else()
        target_link_options(static_analyzer PRIVATE -Wl,--disable-high-entropy-va)
    endif()

    if(STATIC_ANALYZER_HARDENING_DEP_NX)
        target_link_options(static_analyzer PRIVATE -Wl,--nxcompat)
    else()
        target_link_options(static_analyzer PRIVATE -Wl,--disable-nxcompat)
    endif()
endif()

if(STATIC_ANALYZER_HARDENING_STACK_PROTECTOR)
    target_compile_options(static_analyzer PRIVATE -fstack-protector-strong)
else()
    target_compile_options(static_analyzer PRIVATE -fno-stack-protector)
endif()

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
    core file extract capa yara r2 dig net report ui podman ml_api die main mega
)
foreach(module_dir ${ANALYZER_MODULE_DIRS})
    list(APPEND ANALYZER_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/include/${module_dir}")
endforeach()

# cpp-dump: header-only variable dumper used by include/core/debug_dump.hpp
# when the run is started with --debug. Vendored locally like spdlog/ and
# os-libzstd/ (both are untracked too), so a missing checkout is a hard error
# rather than a confusing compile failure deep inside the headers.
set(CPP_DUMP_DIR "${CMAKE_SOURCE_DIR}/cpp-dump")
if(NOT EXISTS "${CPP_DUMP_DIR}/cpp-dump.hpp")
    message(FATAL_ERROR
        "cpp-dump is missing at ${CPP_DUMP_DIR}. Restore the checkout "
        "(https://github.com/philip82148/cpp-dump) - dump.hpp needs "
        "cpp-dump.hpp to compile."
    )
endif()

target_include_directories(static_analyzer PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    ${ANALYZER_INCLUDE_DIRS}
    "${CPP_DUMP_DIR}"
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

# ---------------------------------------------------------------------------
# MEGA SDK (evidence storage / backup recovery) - OFF by default.
#
# The SDK is vendored like spdlog/ and cpp-dump/ and is only reachable from the
# evidence code, so it must not be able to break an ordinary analysis build.
#
# STATUS: this option cannot currently be enabled on this machine. Recorded
# here because the failure is a build-configuration one, not a source one -
# sdk-10.21.0/src/*.cpp syntax-checks clean under MSYS2 UCRT64 g++ -std=c++20.
# The blockers, in the order CMake hits them:
#
#   1. sdk-10.21.0/cmake/modules/sdklib_variables.cmake:11 unconditionally sets
#      CMAKE_GENERATOR_TOOLSET "v142" on WIN32, which the MinGW Makefiles
#      generator rejects outright ("does not support toolset specification").
#   2. No v142 toolset is installed. Visual Studio Build Tools 18.10.2 is
#      present but provides only 14.51 / v145.
#   3. No Windows SDK. C:/Program Files (x86)/Windows Kits/10 has Catalogs and
#      Redist but no Include/ and no Lib/, so cl.exe cannot compile.
#   4. sdklib_variables.cmake:2-4 force USE_CRYPTOPP / USE_SQLITE / USE_SODIUM.
#      The UCRT64 toolchain has libcurl and sqlite3, but no Crypto++ (the
#      libcrypto.pc present is OpenSSL), no libsodium and no ICU.
#
# Enabling it needs the Windows SDK, a v142-or-newer MSVC toolset, and a vcpkg
# manifest supplying cryptopp/libsodium/icu - or the out-of-process sidecar
# design, which builds SDKlib with MSVC on its own and leaves this toolchain
# alone.
# ---------------------------------------------------------------------------

set(MEGA_SDK_DIR "${CMAKE_SOURCE_DIR}/sdk-10.21.0")

if(STATIC_ANALYZER_USE_MEGA_SDK)
    if(NOT EXISTS "${MEGA_SDK_DIR}/CMakeLists.txt")
        message(FATAL_ERROR
            "STATIC_ANALYZER_USE_MEGA_SDK is ON but the SDK is missing at "
            "${MEGA_SDK_DIR}. Unpack the MEGA SDK there "
            "(https://github.com/meganz/sdk), or configure with "
            "-DSTATIC_ANALYZER_USE_MEGA_SDK=OFF to silence this."
        )
    endif()

    # Straight add_subdirectory: the SDK provides MEGA::SDKlib and, being
    # included rather than built top-level, defaults ENABLE_SDKLIB_EXAMPLES,
    # ENABLE_SDKLIB_TESTS and ENABLE_SDKLIB_WERROR to OFF. VCPKG_ROOT is left
    # unset so it resolves dependencies from the system instead of bootstrapping
    # vcpkg mid-configure.
    add_subdirectory("${MEGA_SDK_DIR}" "${CMAKE_BINARY_DIR}/mega-sdk")

    if(TARGET MEGA::SDKlib)
        message(STATUS "MEGA SDK: enabled (${MEGA_SDK_DIR})")
    else()
        message(FATAL_ERROR
            "STATIC_ANALYZER_USE_MEGA_SDK is ON but the SDK did not define the "
            "MEGA::SDKlib target."
        )
    endif()
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

if(STATIC_ANALYZER_USE_MEGA_SDK)
    target_compile_definitions(static_analyzer PRIVATE STATIC_ANALYZER_USE_MEGA_SDK)
    target_link_libraries(static_analyzer PRIVATE MEGA::SDKlib)
endif()

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

# Build identity, resolved once here and compiled in.
#
# The executable should be able to answer "what are you" wherever it ends up -
# on another machine, in an evidence bundle, attached to a bug report - without
# anything shipped beside it. See include/core/build_info.hpp.
find_package(Git QUIET)
set(IA_BUILD_COMMIT "")
set(IA_BUILD_BRANCH "")
set(IA_BUILD_DIRTY 0)
if(GIT_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                    OUTPUT_VARIABLE IA_BUILD_COMMIT
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --abbrev-ref HEAD
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                    OUTPUT_VARIABLE IA_BUILD_BRANCH
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    # Uncommitted changes at configure time. Recorded rather than ignored: a
    # binary built from a dirty tree cannot be reproduced from its commit, and
    # the provenance line is the only place that fact can live.
    execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                    OUTPUT_VARIABLE IA_BUILD_DIRTY_OUT
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    string(REGEX MATCHALL "\n" _nl "${IA_BUILD_DIRTY_OUT}")
    list(LENGTH _nl IA_BUILD_DIRTY)
    # One newline per changed file, minus the trailing one.
    math(EXPR IA_BUILD_DIRTY "${IA_BUILD_DIRTY} - 1")
    if(IA_BUILD_DIRTY LESS 0)
        set(IA_BUILD_DIRTY 0)
    endif()
    if(NOT IA_BUILD_COMMIT)
        # Not actually a checkout after all (a submodule-less export, a tarball
        # that merely has a .git file). Claim nothing rather than claim wrong.
        set(IA_BUILD_COMMIT "")
        set(IA_BUILD_DIRTY 0)
    endif()
endif()

target_compile_definitions(static_analyzer PRIVATE
    STATIC_ANALYZER_MAGIC_DATABASE="${STATIC_ANALYZER_MAGIC_DB}"
    STATIC_ANALYZER_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    IA_BUILD_VERSION="${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.0"
    IA_BUILD_COMMIT="${IA_BUILD_COMMIT}"
    IA_BUILD_BRANCH="${IA_BUILD_BRANCH}"
    IA_BUILD_DIRTY=${IA_BUILD_DIRTY}
    IA_BUILD_DIR="${CMAKE_BINARY_DIR}"
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

# ---------------------------------------------------------------------------
# Unit tests.
#
# Deliberately NOT in `all`: a test target that builds by default is a test
# target nobody runs, and it makes every incremental analyzer build pay for it.
# Build and run it explicitly:
#
#     cmake -S . -B build-ucrt
#     cmake --build build-ucrt --target test_default_pipeline
#     cmake --build build-ucrt --target test_app_paths
#     cmake --build build-ucrt --target test_resume
#
# No gtest. unit/c++/test_main.hpp is the entire harness - a registry, four
# macros and an exit code - which is why this needed no dependency change to get
# a first suite running. See unit/README.md for what belongs here and what does
# not.
#
# One executable per file rather than one binary: they link different amounts of
# the analyzer (app_paths links almost nothing, the default-pipeline check links
# none of it), and a single binary would force the union of all three.
# ---------------------------------------------------------------------------
add_library(unit_harness INTERFACE)
target_include_directories(unit_harness INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++")

# Each test compiles the analyzer sources it exercises directly. They are not a
# library in the main build - the analyzer's own target globs them in - and
# making them one here would mean restructuring that for the sake of tests.
function(ia_add_unit_test name)
  add_executable(${name} ${ARGN})
  # spdlog is linked because the analyzer's headers reference it, not because
  # these tests log anything - which is why console_stub.cpp exists.
  target_link_libraries(${name} PRIVATE unit_harness spdlog::spdlog)
  target_include_directories(${name} PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
      # The analyzer includes its module headers bare ("app_paths.hpp", not
      # "core/app_paths.hpp"), because it appends every include/<module> to the
      # search path. These targets compile analyzer sources, so they need the same
      # list rather than a hand-maintained subset of it.
      ${ANALYZER_INCLUDE_DIRS}
      # This project resolves nlohmann/json as a bare include dir rather than as
      # a find_package target, so the tests follow the same convention instead of
      # introducing one that only they use.
      "${NLOHMANN_JSON_INCLUDE_DIR}")
  if(NOT MSVC)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
  # Built the way static_analyzer is built, deliberately.
  #
  # With STATIC_ANALYZER_STATIC_RUNTIME the analyzer links libgcc and libstdc++
  # statically; these targets did not, so they loaded build-ucrt's copies of
  # libstdc++-6.dll - the ones copied for the analyzer - against a different
  # runtime than they were compiled for. That is not a theoretical hazard: it
  # reproduced as a SIGSEGV inside std::filesystem on the very first call.
  # A test that cannot share the build settings of the code it tests will find
  # bugs that are not there and miss bugs that are.
  if(STATIC_ANALYZER_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(${name} PRIVATE -static-libgcc -static-libstdc++)
  endif()
endfunction()

ia_add_unit_test(test_app_paths
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/test_app_paths.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/app_paths.cpp"
    # The harness prints the suite logo on start and the crash logo on a fault,
    # by calling the analyzer's own banner functions rather than reimplementing
    # them. console_stub.cpp supplies the one console function banner.cpp calls,
    # so the tests do not have to link logging -> redact -> file_hasher just to
    # colour some ASCII art.
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/banner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/console_stub.cpp")

ia_add_unit_test(test_resume
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/test_resume.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/resume.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/banner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/console_stub.cpp")

# Links no analyzer code beyond the banner: it reads the catalog by RUNNING the
# built binary, which is deliberate - a copy of the phase names in the test would
# pass forever after the catalog moved on, which is the bug it exists to catch.
ia_add_unit_test(test_default_pipeline
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/test_default_pipeline.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/banner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/console_stub.cpp")
add_dependencies(test_default_pipeline static_analyzer)

# The planner's pure half - catalog, name resolution, config loading,
# normalization - is reachable without a live sample, so this links the planner
# itself rather than shelling out to the binary. That is a different bargain
# from test_default_pipeline above: linking means these tests exercise the real
# normalize() and the real alias table, but they cannot catch a catalog that is
# correct in memory and wrong on the wire. Keep both.
#
# pipeline_planner.cpp pulls in pipeline.hpp, exporter.hpp and resume.hpp, so
# the source list below is what the linker actually asked for, not a guess.
ia_add_unit_test(test_pipeline_planner
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/test_pipeline_planner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main/pipeline_planner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/app_paths.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/banner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/planner_stubs.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/c++/console_stub.cpp")
target_link_libraries(test_pipeline_planner PRIVATE yaml-cpp)
# pipeline_planner.cpp includes debug_dump_macro.hpp, which pulls cpp-dump.hpp.
target_include_directories(test_pipeline_planner PRIVATE "${CPP_DUMP_DIR}")

# Convenience: build all four. The run_* targets run one each.
add_custom_target(unit_tests
    DEPENDS test_app_paths test_resume test_default_pipeline test_pipeline_planner
    COMMENT "built: test_app_paths, test_resume, test_default_pipeline, test_pipeline_planner")

foreach(_t test_app_paths test_resume test_default_pipeline test_pipeline_planner)
  add_custom_target(run_${_t}
      COMMAND $<TARGET_FILE:${_t}> WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      DEPENDS ${_t} USES_TERMINAL
      COMMENT "unit: ${_t}")
endforeach()
