cmake_minimum_required(VERSION 3.22)
project(antivirus)

set(CMAKE_CXX_STANDARD 17)

set(SOURCE_FILES main.cpp)
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_executable(antivirus main.cpp main.h)


target_link_libraries(antivirus /usr/lib/x86_64-linux-gnu/libcrypto++.a)
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror -static -Lopenssl/openssl-0.9.8k/ -lssl -lcrypto -Iopenssl/openssl-0.9.8k/include)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)