cmake_minimum_required(VERSION 3.22.1)
project("mbguard")

add_library(mbguard SHARED mbguard.cpp)

# 하드닝 B — 심볼 스트립 + 내부 심볼 숨김. JNIEXPORT 3개(JNI_OnLoad/getStatuses/getCoins)만 노출.
# nm/readelf -s로 내부 탐지 함수명이 안 보이게. dlsym(RTLD_DEFAULT,...)은 libc 대상이라 영향 없음.
target_compile_options(mbguard PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_link_options(mbguard PRIVATE -s -Wl,--exclude-libs,ALL)

find_library(log-lib log)
target_link_libraries(mbguard ${log-lib})
