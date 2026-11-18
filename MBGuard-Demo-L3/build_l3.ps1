# MBGuard-Demo-L3 2-pass 빌드 — 네이티브(양 .so) → 내부모듈 암호화(assets) → APK 조립.
# 단일 gradle run에선 inner.so 생성과 assets 병합이 동시라 .enc 선행 불가 → 2-pass.
# 사전요건: Android SDK + NDK 28.0.12674087, JDK 17(JAVA_HOME), Python(py). SDK 경로=local.properties 또는 $env:ANDROID_HOME.
$ErrorActionPreference = 'Stop'
$proj = $PSScriptRoot
Set-Location $proj
$gradle = Join-Path $proj 'gradlew.bat'

Write-Host '== pass1: native build (loader + inner) =='
& $gradle ':app:externalNativeBuildDebug' --console=plain
if ($LASTEXITCODE -ne 0) { throw "native build failed ($LASTEXITCODE)" }

$inner = Get-ChildItem "$proj\app" -Recurse -Filter 'libmbguard_lv2.so' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'arm64-v8a' -and $_.FullName -notmatch '\\assets\\' } |
    Select-Object -First 1
if (-not $inner) { throw 'inner libmbguard_lv2.so not found after native build' }

New-Item -ItemType Directory -Force "$proj\app\src\main\assets" | Out-Null
$enc = "$proj\app\src\main\assets\libmbguard_lv2.so.enc"
Write-Host '== encrypt inner -> assets/.enc =='
py "$proj\tools_build\encrypt_so.py" $inner.FullName $enc
if ($LASTEXITCODE -ne 0) { throw "encrypt failed ($LASTEXITCODE)" }

Write-Host '== pass2: assembleDebug (package loader + .enc asset, exclude inner plaintext) =='
& $gradle ':app:assembleDebug' --console=plain
if ($LASTEXITCODE -ne 0) { throw "assemble failed ($LASTEXITCODE)" }

Write-Host "DONE. APK: $proj\app\build\outputs\apk\debug\app-debug.apk"
