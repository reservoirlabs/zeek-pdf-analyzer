# Usage of this module as follows:
#
#     find_package(PoDoFo)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  PODOFO_ROOT_DIR           Set this variable to the root installation of
#                            PoDoFo if the module has problems finding
#                            the proper installation path.
#
# Variables defined by this module:
#
#  PODOFO_FOUND              System has PoDoFo dev headers/libraries
#  PODOFO_INCLUDE_DIR        The PoDoFo include directories.
#  PODOFO_LIBRARIES          The PoDoFo libraries and linker flags.

find_path(PODOFO_ROOT_DIR
    NAMES include/podofo/podofo.h
)

find_library(PODOFO_LIBRARIES
    NAMES podofo
    HINTS ${PODOFO_ROOT_DIR}/lib
    PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE}
)

find_path(PODOFO_INCLUDE_DIR
    NAMES podofo.h
    HINTS ${PODOFO_ROOT_DIR}/include/podofo
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PoDoFo DEFAULT_MSG
    PODOFO_LIBRARIES
    PODOFO_INCLUDE_DIR
)

mark_as_advanced(
    PODOFO_ROOT_DIR
    PODOFO_LIBRARIES
    PODOFO_INCLUDE_DIR
)
