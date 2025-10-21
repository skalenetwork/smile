cmake_minimum_required(VERSION 3.20)
project(smile LANGUAGES C CXX)

set(CMAKE_TOOLCHAIN_FILE
        "${CMAKE_CURRENT_SOURCE_DIR}/external/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Integrate vcpkg
if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "")
endif()

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

file(GLOB SRC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
add_executable(smile ${SRC_FILES})

target_include_directories(smile PRIVATE src external/libbtc/include)

target_link_libraries(smile
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)