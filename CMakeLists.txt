cmake_minimum_required(VERSION 3.21)

set (PROJ cooker)

project(${PROJ})

set(CMAKE_CXX_STANDARD 17 REQUIRED)

option(SSL "ssl" OFF)
option(ZIB "zib" OFF)
option(WITH_TESTS "build test" OFF)

# boost
find_package(Boost 1.8.3 COMPONENTS url system REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_libraries(${Boost_LIBRARIES})


# cpp-httplib and Lyra
include_directories(${PROJECT_SOURCE_DIR}/3rdParty/)
if (${SSL})
	# ssl
	link_libraries(-lssl)
	link_libraries(-lcrypto)
	add_compile_definitions(CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

# sqlite
link_libraries(-lsqlite3)

# pthread
link_libraries(-lpthread)

# zip
if (${ZIB})
	link_libraries(-lz)
	add_compile_definitions(CPPHTTPLIB_ZLIB_SUPPORT)
endif()

if(${WITH_TEST})
	include(${PROJECT_SOURCE_DIR}/test/CMakeLists.txt)
endif()

add_executable(${PROJ} main.cpp)