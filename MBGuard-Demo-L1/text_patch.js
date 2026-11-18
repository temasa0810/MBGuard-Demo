// libmbguard .text 인라인 패치(=코드 변조) 데모 — 코드 무결성[6] 체크가 잡는지 검증용.
// Interceptor.attach는 arm64서 함수 prologue를 트램폴린으로 덮음 = .text 바이트 변조.
(function(){
  var name='Java_com_mbbypass_mbguarddemo_Guard_getCoins';
  var p=null;
  try{ var m=Process.getModuleByName('libmbguard.so'); p=m.findExportByName(name); }catch(e){}
  if(!p && Module.getGlobalExportByName){ try{ p=Module.getGlobalExportByName(name); }catch(e){} }
  if(p){
    Interceptor.attach(p,{ onLeave:function(r){ r.replace(9999); } }); // 코인 9999 + prologue 패치
    console.log('[text_patch] getCoins inline-hook 설치(libmbguard .text 패치)');
  } else console.log('[text_patch] export 못찾음');
})();
