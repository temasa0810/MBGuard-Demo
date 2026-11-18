// libmbguard.so 로딩 + 탐지 상태/코인 JNI 브리지.
package com.mbbypass.mbguarddemo

object Guard {
    init {
        System.loadLibrary("mbguard")
    }

    // index 0~2 = Frida/후킹 탐지, 3~5 = 루팅 탐지. 값 0=확인중 1=통과 2=탐지됨
    external fun getStatuses(): IntArray

    external fun getCoins(): Int
}
