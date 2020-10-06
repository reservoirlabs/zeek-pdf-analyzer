cmake_minimum_required(VERSION 2.8)

project(ZeekPDFAnalyzer)

set(CMAKE_CXX_FLAGS "-Wfatal-errors ${CMAKE_CXX_FLAGS}")

include(ZeekPlugin)

find_package(PoDoFo)

if (NOT PODOFO_FOUND)
    message(FATAL_ERROR "Cannot find PoDoFo, use --with-podofo=DIR.")
endif ()

include_directories(BEFORE ${PODOFO_INCLUDE_DIR})
bro_plugin_begin(Zeek PDF)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/PDF.cc)
bro_plugin_bif(src/events.bif)
bro_plugin_bif(src/pdf.bif)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_link_library(${PODOFO_LIBRARIES})
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
