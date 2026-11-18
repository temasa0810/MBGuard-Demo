// L3 언패킹 덤프 — 내부 모듈이 로드 시점에 메모리에서 복호되는 순간 평문 ELF를 가로채 저장.
// 로더가 복호한 ELF를 memfd에 write()하는 그 호출을 잡아(ELF 매직 필터) 통째로 덤프한다.
// 사용(florida): adb forward tcp:1234 tcp:1234 후
//   frida -H 127.0.0.1:1234 -f com.mbbypass.mbguarddemo.l3 -l dump_lv2.js
// 또는 attach:  frida -H 127.0.0.1:1234 -n "MBGuard L3 (Packed)" -l dump_lv2.js
// 덤프 후: adb pull <OUT> 하여 Ghidra/radare로 정상 분석 → 암호화가 덤프로 무력화됨을 실증.

var OUT = "/data/data/com.mbbypass.mbguarddemo.l3/files/dumped_libmbguard_lv2.so";
var done = false;

var pWrite = Module.getGlobalExportByName("write");  // Frida 17: top-level getExportByName 제거
Interceptor.attach(pWrite, {
    onEnter: function (args) {
        if (done) return;
        var len = args[2].toInt32();
        if (len < 0x200) return;                     // ELF 헤더보다 작으면 무시
        var p = args[1];
        try {
            var m = new Uint8Array(p.readByteArray(4));
            if (!(m[0] === 0x7f && m[1] === 0x45 && m[2] === 0x4c && m[3] === 0x46)) return; // \x7fELF
            var bytes = p.readByteArray(len);
            var f = new File(OUT, "wb");
            f.write(bytes);
            f.flush();
            f.close();
            done = true;
            console.log("[dump] 평문 ELF 포착(write→memfd): " + len + " bytes");
            console.log("[dump] 저장: " + OUT);
            console.log("[dump] adb pull 로 꺼내 Ghidra에 올리면 암호화된 .so가 평문으로 복원됨.");
        } catch (e) { /* 다른 write는 무시 */ }
    }
});

// 대안 덤프 포인트(참고): android_dlopen_ext 의 extinfo.library_fd(off 0x1c)에서 /proc/self/fd/<fd> 재오픈.
console.log("[dump] write() 후킹 설치 완료 — 앱이 내부 모듈을 복호·로드하는 순간을 대기 중.");
