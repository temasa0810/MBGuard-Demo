cmake_minimum_required(VERSION 3.22.1)
project("mbguard")

# 내부 모듈 — L2 탐지 로직. 빌드 후 암호화되어 assets/libmbguard_lv2.so.enc 로만 동봉되고
# APK packaging(build.gradle packagingOptions)에서 평문은 제외된다. mbg_* export만 노출.
add_library(mbguard_lv2 SHARED guard_inner.cpp)
target_compile_options(mbguard_lv2 PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_link_options(mbguard_lv2 PRIVATE -Wl,--exclude-libs,ALL)
find_library(log-lib log)
target_link_libraries(mbguard_lv2 ${log-lib} dl)

# 로더 — 유일 탑재 lib. 언패커 + JNI 브리지 + 자기방어(init_array anti-debug/anti-frida, 문자열 난독화).
# 하드닝: 심볼 스트립 + visibility hidden(JNIEXPORT 3개만 노출, 내부 함수·anti-debug 심볼 은닉).
add_library(mbguard_loader SHARED loader.cpp)
target_compile_options(mbguard_loader PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_link_options(mbguard_loader PRIVATE -s -Wl,--exclude-libs,ALL)
target_link_libraries(mbguard_loader ${log-lib} android dl)
