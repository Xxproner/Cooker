cmake_minimum_required(VERSION 3.21)

project(urlTree)

add_compile_options(-g)
add_compile_options(-Wall -Wextra -Werror=return-type)

set(CMAKE_CXX_STANDARD 17 REQUIRED)
set(CMAKE_VERBOSE_MAKEFILE off)

# boost
find_package(Boost 1.8.3 COMPONENTS url system container REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_libraries(${Boost_LIBRARIES})


# cpp-httplib and Lyra
include_directories("3rdParty/")
# ssl
include_directories("/usr/local/ssl/include/")
link_directories("/usr/local/ssl/lib64/")
link_libraries(-lssl)
link_libraries(-lcrypto)


# zip
link_libraries(-lz) 

add_executable(main main.cpp)