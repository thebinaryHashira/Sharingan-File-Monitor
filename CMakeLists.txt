cmake_minimum_required(VERSION 3.10)
project(SharinganFileMonitor VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compile options
add_compile_options(-Wall -Wextra)

# Add compile definitions for development build
option(DEBUG_BUILD "Enable debug features" OFF)
if(DEBUG_BUILD)
    add_compile_definitions(DEBUG_BUILD)
    add_compile_options(-g -O0)
else()
    add_compile_options(-O2)
endif()

# Set output directories to parent directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Find required packages
find_package(nlohmann_json 3.9.1 REQUIRED)
find_package(Threads REQUIRED)

# Copy configuration file to working directory if it doesn't exist
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/config.json)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.json.example 
                   ${CMAKE_CURRENT_SOURCE_DIR}/config.json
                   COPYONLY)
endif()

# Add the executable
add_executable(sharingan_file_monitor file_monitor.cpp)

# Link libraries
target_link_libraries(sharingan_file_monitor PRIVATE 
    nlohmann_json::nlohmann_json
    Threads::Threads
    stdc++fs
)

# Optional installation for system-wide usage (commented out by default)
# Uncomment these if you want to install system-wide
# install(TARGETS sharingan_file_monitor DESTINATION bin)
# install(FILES config.json DESTINATION etc/sharinganfilemonitor)

# CPack configuration for package generation
include(CPack)
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "sharingan-file-monitor")
set(CPACK_PACKAGE_VENDOR "Samora Tandon")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sharingan File Monitor - Linux file activity monitoring tool")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "Samora Tandon")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libstdc++6, libnlohmann-json3-dev")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")