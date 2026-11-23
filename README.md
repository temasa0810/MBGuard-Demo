# MBGuard-Demo — Android RASP(Runtime Application Self-Protection)
(L1 → L2 → L3)

직접 만든 **Android 루팅/Frida 탐지 + 네이티브 코드 패킹** 데모입니다. 한 앱을 세 단계로 하드닝하면서, 각 단계의 보호가 **어떻게 분석·우회되는지**, 그리고 다음 단계가 **공격 비용을 얼마나 올리는지**를 보여줍니다. 방어 설계를 공부하기 위한 **교육용**이며, 실제 상용 제품을 대상으로 하지 않습니다.

> ⚠️ **교육용 고지.** 전부 자작 앱입니다. L3의 암호 키는 "패킹이 보안 경계가 아님"을 보이기 위해 **일부러 바이너리에 내장**했습니다. 탐지 로직(su/magisk 경로·Frida 스레드명, hook탐지, 코드 무결성 등)은 공개적으로 알려진 일반 기법이며 특정 벤더 코드가 아닙니다. 방어 연구 목적으로만 사용하세요.

---

## 단계

| 폴더 | 레벨 | 보호 | 정적 분석에서 보이는 것 |
|---|---|---|---|
| `MBGuard-Demo-L1` | **L1 무방비** | 없음 | 문자열·로직 전부 평문 — `strings`·디스어셈블로 즉시 읽힘 |
| `MBGuard-Demo-L2` | **L2 하드닝** | 문자열 XOR 암호화 + 심볼 스트립 + raw-syscall 안티디버그 | 탐지 문자열·함수명은 가려지나 **로직은 디스어셈블로 보임** |
| `MBGuard-Demo-L3` | **L3 패킹** | 로직 자체 암호화 + 로더 하드닝(스트립·난독화·init_array anti-debug) | 디스크엔 **암호문만**. 로드 순간 메모리에서만 복호 → 런타임 덤프 필요 |

각 앱은 공통 UI(탐지 현황판)와 네이티브 탐지 12종(루팅/Frida/디버거/무결성)을 공유하고, 종료 없이 상태만 표시합니다.

## 탐지 요약 (L3)
1. **패킹** — 진짜 탐지 로직을 `libmbguard_lv2.so`로 빌드 → so 암호화 → `assets/*.enc`로만 동봉. APK엔 얇은 로더만.
2. **인메모리 로드** — 로더가 실행 시 복호 → `memfd_create` + `android_dlopen_ext`로 디스크를 거치지 않고 로드.
3. **공격(덤프)** — 복호가 끝난 순간(`write()`→memfd)을 Frida로 후킹해 평문 ELF를 덤프 → 원본과 바이트 일치 복원 (`MBGuard-Demo-L3/dump_lv2.js`).
4. **방어(하드닝)** — 로더에 심볼 스트립 + 문자열 난독화 + `init_array` anti-debug. 분석 감지 시 **복호 키를 오염**시켜 덤프를 차단.
5. **교훈** — 앱(클라이언트)안에 탐지 로직이 존재하는 한 탐지로직을 먼저 무력화하면 덤프는 재개된다. 키가 클라이언트 안에 있는 한 평문은 어느 순간 메모리에 존재한다. **난독화·패킹·anti-debug는 공격 비용을 올리는 지연 수단일 뿐, 신뢰 기점은 클라이언트 밖(서버 검증·하드웨어 증명)에 둬야 한다.**

## 다운로드 (사전 빌드 APK)

직접 빌드하지 않고 바로 설치하려면 **[Releases](https://github.com/temasa0810/MBGuard-Demo/releases/latest)** 에서 L1/L2/L3 APK를 받으세요 (arm64-v8a, debug 서명). 패키지 ID가 달라 세 앱이 동시 설치됩니다. 무결성은 `SHA256SUMS.txt`로 검증합니다.

## 빌드

**사전요건**: Android SDK, **NDK 28.0.12674087**, **JDK 17**(`JAVA_HOME`), (L3) Python 3. 대상 ABI = `arm64-v8a`. SDK 경로는 각 프로젝트의 `local.properties`(`sdk.dir=...`)에 넣거나 `ANDROID_HOME` 환경변수로 지정합니다.

```bash
# L1 / L2 — 표준 빌드
cd MBGuard-Demo-L1   # 또는 MBGuard-Demo-L2
./gradlew assembleDebug        # Windows: .\gradlew.bat assembleDebug

# L3 — 2-pass(네이티브 → 내부모듈 암호화 → APK). Windows PowerShell:
cd MBGuard-Demo-L3
./build_l3.ps1
# (수동 등가) ./gradlew :app:externalNativeBuildDebug
#            py tools_build/encrypt_so.py <build된 libmbguard_lv2.so> app/src/main/assets/libmbguard_lv2.so.enc
#            ./gradlew :app:assembleDebug
```

APK: `<project>/app/build/outputs/apk/debug/app-debug.apk` → `adb install -r <apk>`.

## L3 덤프 데모 (선택)
루팅 기기 + Frida가 있으면 암호화된 내부 모듈을 로드 순간에 덤프해 복원할 수 있습니다.

```bash
# 하드닝 전 로더: 덤프 성공(원본 복원)
frida -H 127.0.0.1:<port> -f com.mbbypass.mbguarddemo.l3 -l MBGuard-Demo-L3/dump_lv2.js
# (helper) py MBGuard-Demo-L3/dump_run.py
# 하드닝 로더: init_array가 Frida를 감지해 키를 오염 → 복호 실패 → 덤프 ABSENT
```

## 관련
방법론·공방 상세: 포트폴리오 케이스 "네이티브 코드 패킹 — 언패킹·하드닝".

## 라이선스
MIT — `LICENSE` 참조.
