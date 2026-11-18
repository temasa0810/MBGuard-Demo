'use strict';
// MBGuard-Demo 탐지 우회 훅 — ①스레드명 은폐(/proc comm rename, 무훅) ②access GOT 리다이렉트(트램폴린-free)
//  ③getInstalledPackages 권한지문 필터(Java) ④fgets GOT(mount magisk+rwx 라인 스킵) ⑤dladdr GOT(GOT 무결성 우회)
//  ⑥Guard.getStatuses 판정 전부 CLEAR(verdict-level, 라운드7) ⑦.text 패치+baseline 해시 overwrite(코드무결성 우회, 라운드8). 데모 전용.
// ★Java 브리지 사용 → frida-compile로 .compiled.js 번들 후 로드할 것.
import Java from 'frida-java-bridge';

// ---- libc export 헬퍼 (frida17: top-level getExportByName 제거) ----
function cexp(n){ var m=Process.getModuleByName('libc.so'); var p=null;
  try{p=m.findExportByName(n);}catch(e){}
  if(!p&&Module.getGlobalExportByName){ try{p=Module.getGlobalExportByName(n);}catch(e){} }
  return p; }

// ---- ① 스레드명 은폐 (/proc write only, no Interceptor) ----
var BENIGN='pool-thread-9', RE=/frida|gum|gmain|gdbus|linjector|pool-frida|js-loop|pool-spawner/i;
var openF=new NativeFunction(cexp('open'),'int',['pointer','int']);
var readF=new NativeFunction(cexp('read'),'long',['int','pointer','ulong']);
var writeF=new NativeFunction(cexp('write'),'long',['int','pointer','ulong']);
var closeF=new NativeFunction(cexp('close'),'int',['int']);
var opendirF=new NativeFunction(cexp('opendir'),'pointer',['pointer']);
var readdirF=new NativeFunction(cexp('readdir'),'pointer',['pointer']);
var closedirF=new NativeFunction(cexp('closedir'),'int',['pointer']);
var prctlF=new NativeFunction(cexp('prctl'),'int',['int','pointer','long','long','long']);
function readComm(t){ try{ var fd=openF(Memory.allocUtf8String('/proc/self/task/'+t+'/comm'),0)|0; if(fd<0)return'';
  var b=Memory.alloc(64); var n=readF(fd,b,63)|0; closeF(fd); return n>0?b.readUtf8String(n).replace(/[\r\n]/g,''):''; }catch(e){return'';} }
function writeComm(t,nm){ try{ var fd=openF(Memory.allocUtf8String('/proc/self/task/'+t+'/comm'),1)|0; if(fd<0)return;
  var b=Memory.allocUtf8String(nm); writeF(fd,b,nm.length); closeF(fd);}catch(e){} }
function renameAll(){ var d=opendirF(Memory.allocUtf8String('/proc/self/task')); if(d.isNull())return; var e;
  while(!((e=readdirF(d)).isNull())){ var nm=e.add(19).readCString(); if(!nm||!/^[0-9]+$/.test(nm))continue;
    var c=readComm(nm); if(c&&RE.test(c)) writeComm(nm,BENIGN); } closedirF(d); }
renameAll();
setInterval(function(){ try{prctlF(15,Memory.allocUtf8String(BENIGN),0,0,0);}catch(e){} renameAll(); },300);

// ---- ② access() 우회 (★트램폴린-free): libmbguard.so의 access import(GOT) 리다이렉트 ----
// Interceptor.attach(access)는 access 코드 prologue를 트램폴린으로 패치→트램폴린 탐지에 걸림.
// 대신 호출 모듈의 import 슬롯(GOT)만 교체해 access 코드는 무손상 유지→트램폴린 체크 통과.
// = 실제 ACE 우회의 no-trampoline(테이블/methodPointer 리다이렉트) 기법.
(function(){
  try {
    var m = Process.getModuleByName('libmbguard.so');
    var acc = null, imps = m.enumerateImports();
    for (var i=0;i<imps.length;i++){ if(imps[i].name==='access'){ acc=imps[i]; break; } }
    if(!acc || !acc.slot){ console.log('[notramp] access import/slot 못찾음'); return; }
    var realAccess = new NativeFunction(acc.address,'int',['pointer','int']);
    var cb = new NativeCallback(function(pathPtr, mode){
      try { var p=pathPtr.readUtf8String();
        if(p && (p.slice(-3)==='/su' || p.indexOf('magisk')>=0 || p.indexOf('/debug_ramdisk')>=0)) return -1;
      } catch(e){}
      return realAccess(pathPtr, mode);
    }, 'int', ['pointer','int']);
    globalThis.__mbg_access_cb = cb; // GC 방지
    try { Memory.protect(acc.slot, Process.pointerSize, 'rw-'); } catch(e){}
    acc.slot.writePointer(cb);
    console.log('[mbguard_bypass] access GOT 리다이렉트 활성(트램폴린-free)');
  } catch(e){ console.log('[notramp err] '+e); }
})();

// ---- ④ mount 우회 (★트램폴린-free GOT): fgets 계열에서 magisk 마운트 라인 스킵 ----
// mount 체크는 fgets로 /proc/self/mounts를 읽음. NDK FORTIFY로 실제 심볼은 __fgets_chk(4-arg).
// 두 import 슬롯을 모두 교체해 magisk/debug_ramdisk 포함 라인은 건너뛰고 다음 라인을 반환.
(function(){
  try {
    var m = Process.getModuleByName('libmbguard.so');
    var imps = m.enumerateImports();
    function findImp(nm){ for (var i=0;i<imps.length;i++) if(imps[i].name===nm) return imps[i]; return null; }
    var SKIP = /magisk|\/debug_ramdisk|KSU|worker|rwxp/;  // rwxp=rwx 익명메모리 라인도 숨김(rwx 체크 우회)
    globalThis.__mbg_mount_cbs = [];

    // FORTIFY 경로: fgets(buf,sizeof,f) → __fgets_chk(buf,size,f,bos)
    var impC = findImp('__fgets_chk');
    if (impC && impC.slot) {
      var realC = new NativeFunction(impC.address,'pointer',['pointer','int','pointer','size_t']);
      var cbC = new NativeCallback(function(buf, size, stream, bos){
        while(true){ var r=realC(buf,size,stream,bos); if(r.isNull())return r;
          var line=''; try{line=buf.readUtf8String();}catch(e){return r;}
          if(line && SKIP.test(line)) continue; return r; }
      }, 'pointer', ['pointer','int','pointer','size_t']);
      globalThis.__mbg_mount_cbs.push(cbC);
      try { Memory.protect(impC.slot, Process.pointerSize, 'rw-'); } catch(e){}
      impC.slot.writePointer(cbC);
      console.log('[mbguard_bypass] __fgets_chk GOT 리다이렉트 활성(mount)');
    }
    // 일반 fgets 경로(fallback)
    var impG = findImp('fgets');
    if (impG && impG.slot) {
      var realG = new NativeFunction(impG.address,'pointer',['pointer','int','pointer']);
      var cbG = new NativeCallback(function(buf, size, stream){
        while(true){ var r=realG(buf,size,stream); if(r.isNull())return r;
          var line=''; try{line=buf.readUtf8String();}catch(e){return r;}
          if(line && SKIP.test(line)) continue; return r; }
      }, 'pointer', ['pointer','int','pointer']);
      globalThis.__mbg_mount_cbs.push(cbG);
      try { Memory.protect(impG.slot, Process.pointerSize, 'rw-'); } catch(e){}
      impG.slot.writePointer(cbG);
    }
  } catch(e){ console.log('[mount err] '+e); }
})();

console.log('[mbguard_bypass] thread-hide + access/fgets GOT 스푸핑 활성');

// ---- ⑤ GOT 무결성 우회: dladdr를 항상 "정상 모듈"로 응답하게 GOT 리다이렉트 ----
// GOT 무결성 체크는 import GOT값에 dladdr를 걸어 익명메모리면 탐지. dladdr은 watch목록에 없으니
// 그 import 슬롯만 바꿔 리다이렉트된 GOT도 "libc에 속함"으로 위장 → 체크가 못 잡음.
(function(){
  try {
    var m = Process.getModuleByName('libmbguard.so');
    var imp = null, imps = m.enumerateImports();
    for (var i=0;i<imps.length;i++){ if(imps[i].name==='dladdr'){ imp=imps[i]; break; } }
    if(!imp || !imp.slot){ console.log('[got-bypass] dladdr import/slot 못찾음'); return; }
    var realDladdr = new NativeFunction(imp.address,'int',['pointer','pointer']);
    var fakeName = Memory.allocUtf8String('/system/lib64/libc.so'); // 가짜 dli_fname
    var P = Process.pointerSize;
    var cb = new NativeCallback(function(addr, info){
      var r = realDladdr(addr, info);
      if (r === 0 && !info.isNull()) {              // 익명(실패)이면 성공으로 위장
        try {
          info.writePointer(fakeName);              // dli_fname = libc
          info.add(P).writePointer(m.base);         // dli_fbase = 유효주소
          info.add(P*2).writePointer(ptr(0));       // dli_sname
          info.add(P*3).writePointer(ptr(0));       // dli_saddr
        } catch(e){}
        return 1;
      }
      return r;
    }, 'int', ['pointer','pointer']);
    globalThis.__mbg_dladdr_cb = cb;
    try { Memory.protect(imp.slot, P, 'rw-'); } catch(e){}
    imp.slot.writePointer(cb);
    console.log('[mbguard_bypass] dladdr GOT 리다이렉트 활성(GOT 무결성 우회)');
  } catch(e){ console.log('[got-bypass err] '+e); }
})();

// ---- ③ 권한 지문 우회 (Java): getInstalledPackages에서 지문권한 보유 앱 제거 ----
Java.perform(function(){
  try {
    var APM = Java.use('android.app.ApplicationPackageManager');
    var PackageInfo = Java.use('android.content.pm.PackageInfo');
    var ArrayList = Java.use('java.util.ArrayList');
    var U = 'android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION';
    var H = 'android.permission.HIDE_OVERLAY_WINDOWS';
    APM.getInstalledPackages.overload('int').implementation = function(flags){
      var list = this.getInstalledPackages(flags);
      try {
        var out = ArrayList.$new();
        var n = list.size();
        for (var i=0;i<n;i++){
          var pi = Java.cast(list.get(i), PackageInfo);
          var perms = pi.requestedPermissions.value;
          var hu=false, hh=false;
          if (perms){ for (var j=0;j<perms.length;j++){ var s=''+perms[j]; if(s===U)hu=true; else if(s===H)hh=true; } }
          if (!(hu&&hh)) out.add(pi);   // 지문(두 권한 동반) 앱만 리스트에서 누락
        }
        return out;
      } catch(e){ console.log('[pkg filter err] '+e); return list; }
    };
    console.log('[mbguard_bypass] getInstalledPackages 권한지문 필터 활성');
  } catch(e){ console.log('[java hook err] '+e); }
});

// ---- ⑥ 판정(verdict) 레벨 우회 (라운드7): Guard.getStatuses()를 전부 CLEAR(1)로 교체 ----
// 라4~6 강화로 rwx·GOT·코드무결성을 각개격파(check-level)하는 건 매우 어렵다. 그래서 결과 "보고 함수"를
// Java 레벨서 가로채 현황판에 전부 통과로 보고한다. 네이티브 .text 미패치(코드무결성 통과)·단일 지점.
// ★이건 check-level이 아니라 verdict-level 우회 — "클라가 보고한 판정을 신뢰"하는 구조의 약점을 찌름.
//   네이티브는 여전히 탐지(내부 g_status는 적색)하지만 UI로 가는 보고를 바꿔치기. 실제 RASP가 판정을
//   서버서 재검증해야 하는 이유(로컬 위조는 서버를 못 속임). CLEAR=1 / DETECTED=2 (네이티브 정의와 일치).
Java.perform(function(){
  try {
    var G = Java.use('com.mbbypass.mbguarddemo.Guard');
    G.getStatuses.implementation = function(){
      var orig = this.getStatuses();         // 원본 호출(길이만 사용)
      var n = orig.length;
      var out = Java.array('int', Array.apply(null, {length:n}).map(function(){ return 1; }));
      return out;                            // 전부 CLEAR 보고
    };
    console.log('[mbguard_bypass] Guard.getStatuses 판정 전부 CLEAR 보고(verdict-level)');
  } catch(e){ console.log('[verdict hook err] '+e); }
});

// ---- ⑦ 코드 무결성(.text 자가해시) 우회 (라운드8): .text 패치 + baseline 해시 overwrite ----
// 코드무결성[6]은 로드시 .text FNV-1a 해시를 g_text_hash(쓰기영역)에 저장→매루프 비교. baseline이 인프로세스
// 쓰기영역이라, .text를 패치한 뒤 새 해시를 재계산해 g_text_hash에 덮어쓰면 체크가 "일치"로 통과한다.
// (여기선 getCoins=9999로 .text 변조를 시연하고 그 후 baseline을 고쳐 무결성 탐지를 무력화.)
(function(){
  try{
    var m = Process.getModuleByName('libmbguard.so');
    var base = m.base;
    var e_phoff = base.add(0x20).readU64();
    var e_phnum = base.add(0x38).readU16();
    var e_phentsize = base.add(0x36).readU16();
    var segAddr=null, segLen=0;
    for (var i=0;i<e_phnum;i++){                     // ELF64 Phdr → PF_X PT_LOAD(=네이티브 .text 범위)
      var ph = base.add(e_phoff).add(i*e_phentsize);
      if (ph.readU32()===1 && (ph.add(4).readU32()&1)){
        segAddr = base.add(ph.add(0x10).readU64());
        segLen  = ph.add(0x28).readU64().toNumber();
        break;
      }
    }
    if(!segAddr){ console.log('[int-bypass] .text 세그먼트 못찾음'); return; }
    var MASK=0xFFFFFFFFFFFFFFFFn, PRIME=1099511628211n, OFF=1469598103934665603n;
    function fnv(){ var u8=new Uint8Array(segAddr.readByteArray(segLen)); var h=OFF;
      for(var i=0;i<segLen;i++){ h=((h^BigInt(u8[i]))*PRIME)&MASK; } return h; }
    function toLE(big){ var b=[]; for(var i=0;i<8;i++){ b.push(Number(big&0xFFn)); big>>=8n; } return b; }
    var H0=fnv();                                    // 패치전 해시 → g_text_hash 슬롯 스캔
    var pat=toLE(H0).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(' ');
    var slot=null;
    Process.enumerateRanges('rw-').forEach(function(r){ if(slot)return;
      if(r.base.compare(base)>=0 && r.base.compare(base.add(m.size))<0){
        try{ var f=Memory.scanSync(r.base,r.size,pat); if(f.length) slot=f[0].address; }catch(e){} } });
    if(!slot){ console.log('[int-bypass] g_text_hash 슬롯 못찾음'); return; }
    var gc=m.findExportByName('Java_com_mbbypass_mbguarddemo_Guard_getCoins');
    if(gc){ Interceptor.attach(gc,{ onLeave:function(r){ r.replace(9999); } }); Interceptor.flush(); } // .text 변조
    slot.writeByteArray(toLE(fnv()));                // 패치후 새 해시 overwrite → check_integrity 통과
    console.log('[mbguard_bypass] 코드무결성 우회: .text 패치 후 baseline 해시 overwrite');
  }catch(e){ console.log('[int-bypass err] '+e); }
})();
