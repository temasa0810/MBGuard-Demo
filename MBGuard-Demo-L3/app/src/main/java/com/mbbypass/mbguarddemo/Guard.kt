// libmbguard_loader.so 로딩 + L3 언패커 부트스트랩(에셋→복호→인메모리 로드) + 탐지상태/코인 JNI 브리지.
package com.mbbypass.mbguarddemo

import android.content.res.AssetManager

object Guard {
    init {
        System.loadLibrary("mbguard_loader")
    }

    @Volatile private var booted = false

    // 내부 모듈을 암호화 에셋에서 복호해 메모리에 로드한다. getStatuses/getCoins 전에 1회 호출.
    fun init(assets: AssetManager, cacheDir: String) {
        if (booted) return
        nativeInit(assets, cacheDir)
        booted = true
    }

    private external fun nativeInit(assets: AssetManager, cacheDir: String)

    // index 0~11 = 네이티브 탐지(내부 모듈), 값 0=확인중 1=통과 2=탐지됨
    external fun getStatuses(): IntArray

    external fun getCoins(): Int
}
