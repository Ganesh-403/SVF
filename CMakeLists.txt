cmake_minimum_required(VERSION 3.14)
project(SVF VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB_RECURSE SRC_FILES "src/*.cpp")

add_executable(svf ${SRC_FILES})
target_compile_definitions(svf PRIVATE _FILE_OFFSET_BITS=64)

# Link libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(svf pthread fuse)
else()
    target_link_libraries(svf pthread)
endif()
