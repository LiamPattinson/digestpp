cmake_minimum_required(VERSION 3.13)

project(
        digestpp
    VERSION
        0.1.0 
    DESCRIPTION 
        "C++ header-only message digest library"
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(DIGESTPP_BUILD_TESTS "Build tests" OFF)

# windows.h will conflict with min functions in digestcpp
# Because of macro definitions of min and max
# So tell the compiler to exclude min and max macros in windows
if(WIN32)
    add_definitions(-DNOMINMAX)
    add_definitions(-DNOGDI)
endif()


add_library(digestpp INTERFACE)
add_library(digestpp::digestpp ALIAS digestpp)
target_include_directories(
    digestpp
    INTERFACE
    $<BUILD_INTERFACE:${digestpp_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Set rules for installing targets
set(digestpp_targets digestpp)
install(TARGETS ${digestpp_targets}
        EXPORT digestppTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install export file, which contains code to allow other projects to import this project
install(
    EXPORT digestppTargets
    FILE digestppTargets.cmake
    NAMESPACE digestpp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/digestpp
)

# Install this project's include dir, so projects importing it can access it
install(DIRECTORY ./include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Create files that allow installed project to be discovered using find_package
configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/digestppConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/digestppConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/digestpp
)

write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/digestppConfigVersion.cmake"
    VERSION  ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)

# Specify where to install the config files we generated
install(
    FILES 
        "${PROJECT_BINARY_DIR}/digestppConfig.cmake"
        "${PROJECT_BINARY_DIR}/digestppConfigVersion.cmake"
    DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}/cmake/digestpp
)

# Configure the .in pkg-config file and install
CONFIGURE_FILE(
    "${PROJECT_SOURCE_DIR}/cmake/digestpp.pc.in"
    "${PROJECT_BINARY_DIR}/digestpp.pc"
    @ONLY
)

INSTALL(
    FILES 
        ${PROJECT_BINARY_DIR}/digestpp.pc
    DESTINATION
        ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)

if(DIGESTPP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(./test)
endif()

