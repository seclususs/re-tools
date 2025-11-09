find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
find_library(CAPSTONE_LIBRARY NAMES capstone)

set(CAPSTONE_LIBRARIES ${CAPSTONE_LIBRARY})
set(CAPSTONE_INCLUDE_DIRS ${CAPSTONE_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Capstone
    DEFAULT_MSG
    CAPSTONE_LIBRARY CAPSTONE_INCLUDE_DIR
)

mark_as_advanced(CAPSTONE_INCLUDE_DIR CAPSTONE_LIBRARY)