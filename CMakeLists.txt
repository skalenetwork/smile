cmake_minimum_required(VERSION 3.20)
project(smile-demo LANGUAGES C CXX)

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


add_executable(smile-demo
        src/main.cpp
        src/smile_sim.cpp
        src/smile_kdf.cpp
        src/smile_wallet.cpp
)

target_include_directories(smile-demo PRIVATE src external/libbtc/include)

target_link_libraries(smile-demo
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)