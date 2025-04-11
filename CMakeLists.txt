cmake_minimum_required(VERSION 3.13)
project(FinalDefiSecureGateway VERSION 0.2.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -flto")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG")
endif()

# Add security flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z noexecstack -z relro -z now")

# Find required packages
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem program_options uuid)
find_package(ZLIB REQUIRED)

# Check if liboqs and libsodium are installed system-wide
find_library(LIBOQS_LIBRARY oqs)
find_library(LIBSODIUM_LIBRARY sodium)

# If not found, use local versions from external directory
if(NOT LIBOQS_LIBRARY)
    add_subdirectory(external/liboqs)
    set(LIBOQS_LIBRARY oqs)
    set(LIBOQS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/liboqs/include)
endif()

if(NOT LIBSODIUM_LIBRARY)
    add_subdirectory(external/libsodium)
    set(LIBSODIUM_LIBRARY sodium)
    set(LIBSODIUM_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/libsodium/src/libsodium/include)
endif()

# Set include directories
include_directories(include)
include_directories(${LIBOQS_INCLUDE_DIR})
include_directories(${LIBSODIUM_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIRS})

# Define source files
set(SDK_SOURCES
    src/sdk/AttestationStore.cpp
    src/sdk/CircuitBreaker.cpp
    src/sdk/DilithiumSignature.cpp
    src/sdk/FinalChainSubmitter.cpp
    src/sdk/FinalDefiSDK.cpp
    src/sdk/KyberEncryption.cpp
    src/sdk/MessageCompression.cpp
    src/sdk/MerkleTree.cpp
    src/sdk/NodeRegistry.cpp
    src/sdk/PQNetworking.cpp
    src/sdk/SecureLogger.cpp
    src/sdk/ThresholdCrypto.cpp
    src/sdk/ThreadPool.cpp
    src/sdk/TransactionStore.cpp
)

set(GATEWAY_SOURCES
    src/secure_gateway/AuditLayer.cpp
    src/secure_gateway/HTTPServer.cpp
    src/secure_gateway/NodeRegistrySecure.cpp
    src/secure_gateway/SecureGateway.cpp
    src/secure_gateway/TransactionProcessor.cpp
)

# Main executable
add_executable(secure_gateway 
    src/main.cpp
    ${SDK_SOURCES}
    ${GATEWAY_SOURCES}
)

# Link libraries
target_link_libraries(secure_gateway
    ${LIBOQS_LIBRARY}
    ${LIBSODIUM_LIBRARY}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ZLIB::ZLIB
    Threads::Threads
    -ldl
    -lrt
)

# Set output directory
set_target_properties(secure_gateway PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Install targets
install(TARGETS secure_gateway DESTINATION bin)

# Install configuration
install(FILES config/secure_gateway.conf DESTINATION /etc/finaldefi)

# Documentation
option(BUILD_DOCS "Build documentation" OFF)
if(BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        configure_file(docs/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
        add_custom_target(docs
            ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen" VERBATIM
        )
    endif()
endif()

# Testing
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Create version header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/finaldefi/version.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/finaldefi/version.hpp
)

# Print configuration summary
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}: ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}")
message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
message(STATUS "LIBOQS_LIBRARY: ${LIBOQS_LIBRARY}")
message(STATUS "LIBSODIUM_LIBRARY: ${LIBSODIUM_LIBRARY}")