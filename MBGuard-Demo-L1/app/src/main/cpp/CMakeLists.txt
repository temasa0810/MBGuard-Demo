cmake_minimum_required(VERSION 3.22.1)
project("mbguard")

add_library(mbguard SHARED mbguard.cpp)

find_library(log-lib log)
target_link_libraries(mbguard ${log-lib})
