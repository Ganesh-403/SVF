cmake_minimum_required(VERSION 3.14)
project(SVF VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB_RECURSE SRC_FILES "src/*.cpp")

add_executable(svf ${SRC_FILES})

# Link libraries
target_link_libraries(svf pthread)
