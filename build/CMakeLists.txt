# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(IPFE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
  
add_executable(test_IPFE ../test/test_IPFE.cpp)

target_link_libraries(test_IPFE ${OPENSSL_LIBRARIES})