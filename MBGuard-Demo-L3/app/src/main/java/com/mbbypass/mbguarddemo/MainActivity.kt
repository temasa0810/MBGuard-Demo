// 탐지 우회 현황판 — 네이티브 탐지 상태를 0.5초마다 폴링해 실시간 표시.
package com.mbbypass.mbguarddemo

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())

    // 인덱스 0~11 = 네이티브 getStatuses(), 12~14 = Java 탐지(Kotlin)
    private val labels = listOf(
        "스레드명 스캔 (/proc/self/task)",
        "메모리맵 스캔 (/proc/self/maps)",
        "ptrace 디버거 (TracerPid, 파일 API)",
        "트램폴린/인라인훅 (prologue 패치)",
        "실행권한 익명메모리 (rwx/W^X)",
        "GOT/import 무결성 (포인터 검증)",
        "코드 무결성 (.text 자가해시)",
        "안티디버그 (TracerPid, raw syscall)",
        "su 바이너리",
        "Magisk 흔적 (파일)",
        "test-keys 빌드태그",
        "mount 정보 (magisk 마운트)",
        "루트 앱 패키지 (PackageManager)",
        "루트 앱 권한 지문 (매니페스트 권한)",
        "APK 서명 무결성 (anti-repackaging)",
    )

    // 원본 서명 인증서 SHA-256 (리패키징/리사인하면 달라짐). apksigner로 산출.
    private val EXPECTED_SIG = "4366ff3d44024aafda77a16275544191d279fd653f6210e2cc00052d63c40afe"

    // 알려진 루트 매니저 패키지 — 숨김/리네임 시엔 못 잡음(mount 탐지가 보완)
    private val rootPackages = listOf(
        "com.topjohnwu.magisk",
        "com.topjohnwu.magisk.stub",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.kingroot.kinguser",
        "com.kingouser.com",
        "me.weishu.kernelsu",
        "com.yellowes.su",
    )

    // Magisk stub 권한 지문 — 리네임/난독화해도 매니페스트 권한은 못 숨김.
    // 이 두 권한의 동반 보유는 일반 앱엔 거의 없어 숨긴 Magisk 식별에 유효.
    private val fpPerms = listOf(
        "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION",
        "android.permission.HIDE_OVERLAY_WINDOWS",
    )

    // Java 전수 열거는 비싸므로 1.5초 캐시(훅 시 ~1.5초 내 반영)
    private var javaCacheAt = 0L
    private var pkgStatus = 0
    private var permStatus = 0
    private var sigStatus = 0

    private val rows = ArrayList<TextView>()
    private lateinit var summary: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // L3: 암호화된 내부 모듈을 복호해 메모리에 로드(부트스트랩). 이후 상태/코인 조회 가능.
        Guard.init(assets, cacheDir.absolutePath)

        summary = findViewById(R.id.summary)
        findViewById<TextView>(R.id.coins).text = "코인(조작 대상): ${Guard.getCoins()}"

        val container = findViewById<LinearLayout>(R.id.container)
        addHeader(container, "LEVEL 3 (Packed) — 네이티브 로직 암호화 · 로드시 인메모리 복호 · 로더 분리")
        addHeader(container, "Frida / 후킹 탐지")
        for (i in 0..7) rows.add(addRow(container))
        addHeader(container, "루팅 탐지")
        for (i in 8..13) rows.add(addRow(container))
        addHeader(container, "앱 무결성 탐지")
        for (i in 14..14) rows.add(addRow(container))

        poll()
    }

    // 앱 무결성 탐지 — 자기 서명 인증서 SHA-256을 원본 기대값과 대조(anti-repackaging).
    // 우회=getPackageInfo/signingInfo Java 후킹으로 원본 서명 반환 강제(verdict류 공략).
    private fun checkSignature(): Int {
        return try {
            val d = currentSigDigest()
            if (d != null && d.equals(EXPECTED_SIG, ignoreCase = true)) 1 else 2
        } catch (_: Exception) { 1 }  // 예외는 보수적 통과(오탐 방지), 핵심 신호는 불일치
    }

    private fun currentSigDigest(): String? {
        val pm = packageManager
        val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
        }
        if (sigs.isNullOrEmpty()) return null
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(sigs[0].toByteArray()).joinToString("") { "%02x".format(it) }
    }

    // Java 계층 루팅 탐지 — 전수 열거 1회로 패키지명+라벨 동시 판정(1.5초 캐시)
    private fun refreshJava() {
        val now = SystemClock.uptimeMillis()
        if (javaCacheAt != 0L && now - javaCacheAt < 1500) return
        javaCacheAt = now
        val pm = packageManager

        // ① 알려진 패키지명 조회
        pkgStatus = 1
        for (p in rootPackages) {
            try { pm.getPackageInfo(p, 0); pkgStatus = 2; break }
            catch (_: PackageManager.NameNotFoundException) {}
        }

        // ② 권한 지문: 사용자 설치 앱 중 Magisk stub의 희귀 권한 조합 보유 앱 탐지.
        // 시스템 패키지(android 프레임워크 등)는 모든 권한을 선언하므로 제외(오탐 방지).
        permStatus = 1
        for (pi in pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            val ai = pi.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            val perms = pi.requestedPermissions ?: continue
            if (fpPerms.all { perms.contains(it) }) { permStatus = 2; break }
        }

        // ③ APK 서명 무결성 (anti-repackaging)
        sigStatus = checkSignature()
    }

    private fun addHeader(parent: LinearLayout, text: String) {
        val tv = TextView(this)
        tv.text = text
        tv.textSize = 18f
        tv.setTypeface(null, Typeface.BOLD)
        tv.setPadding(0, 28, 0, 8)
        parent.addView(tv)
    }

    private fun addRow(parent: LinearLayout): TextView {
        val tv = TextView(this)
        tv.textSize = 15f
        tv.setPadding(0, 10, 0, 10)
        parent.addView(tv)
        return tv
    }

    private fun poll() {
        refreshJava()
        val native = Guard.getStatuses()                               // 0~10
        val st = native + intArrayOf(pkgStatus, permStatus, sigStatus) // +11 패키지, +12 권한지문, +13 서명
        var passed = 0
        for (i in rows.indices) {
            val s = if (i < st.size) st[i] else 0
            val word: String
            val color: Int
            when (s) {
                1 -> { passed++; word = "통과"; color = Color.rgb(0x2e, 0x7d, 0x32) }
                2 -> { word = "탐지됨"; color = Color.rgb(0xc6, 0x28, 0x28) }
                else -> { word = "확인중"; color = Color.GRAY }
            }
            rows[i].text = "●  ${labels[i]}  —  $word"
            rows[i].setTextColor(color)
        }
        summary.text = "우회 진행   $passed / ${rows.size} 통과"
        handler.postDelayed({ poll() }, 500)
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }
}
