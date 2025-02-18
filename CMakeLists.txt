cmake_minimum_required(VERSION 3.21)

project(cooker)

set(CMAKE_CXX_STANDARD 17 REQUIRED)
set(CMAKE_VERBOSE_MAKEFILE off)

add_compile_options(-g -DDEGUB)

# boost
find_package(Boost 1.8.3 COMPONENTS url system REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_libraries(${Boost_LIBRARIES})

# cpp-httplib and Lyra
include_directories("3rdParty/")

# ssl
include_directories("/usr/local/ssl/include/")
link_directories("/usr/local/ssl/lib64/")
link_libraries(-lssl)
link_libraries(-lcrypto)
link_libraries(-lsqlite3)
link_libraries(-lpthread)


# zip
link_libraries(-lz) 

add_executable(cooker main.cpp)