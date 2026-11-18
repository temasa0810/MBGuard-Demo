// 코드무결성(.text 자가해시) 우회 검증용 standalone — .text 패치 + baseline 해시 overwrite.
// g_text_hash(쓰기영역)에 저장된 baseline을, 패치 후 새 해시로 덮어써 check_integrity를 "일치"로 속임.
(function(){
  try{
    var m = Process.getModuleByName('libmbguard.so');
    var base = m.base;
    // ELF64 Phdr 파싱 → PF_X PT_LOAD 세그먼트(네이티브 g_text_addr/len과 동일 범위)
    var e_phoff = base.add(0x20).readU64();
    var e_phnum = base.add(0x38).readU16();
    var e_phentsize = base.add(0x36).readU16();
    var segAddr=null, segLen=0;
    for (var i=0;i<e_phnum;i++){
      var ph = base.add(e_phoff).add(i*e_phentsize);
      if (ph.readU32()===1 && (ph.add(4).readU32()&1)){ // PT_LOAD & PF_X
        segAddr = base.add(ph.add(0x10).readU64());
        segLen  = ph.add(0x28).readU64().toNumber();
        break;
      }
    }
    if(!segAddr){ console.log('[int] .text 세그먼트 못찾음'); return; }
    console.log('[int] .text seg='+segAddr+' len='+segLen);
    var MASK=0xFFFFFFFFFFFFFFFFn, PRIME=1099511628211n, OFF=1469598103934665603n;
    function fnv(){ var u8=new Uint8Array(segAddr.readByteArray(segLen)); var h=OFF;
      for(var i=0;i<segLen;i++){ h=((h^BigInt(u8[i]))*PRIME)&MASK; } return h; }
    function toLE(big){ var b=[]; for(var i=0;i<8;i++){ b.push(Number(big&0xFFn)); big>>=8n; } return b; }
    // 1) 패치전 H0 → 데이터영역서 g_text_hash 슬롯 스캔
    var H0=fnv();
    var pat=toLE(H0).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(' ');
    var slot=null;
    Process.enumerateRanges('rw-').forEach(function(r){ if(slot)return;
      if(r.base.compare(base)>=0 && r.base.compare(base.add(m.size))<0){
        try{ var f=Memory.scanSync(r.base,r.size,pat); if(f.length) slot=f[0].address; }catch(e){} } });
    if(!slot){ console.log('[int] g_text_hash 슬롯 못찾음'); return; }
    console.log('[int] g_text_hash slot='+slot+' H0=0x'+H0.toString(16));
    // 2) .text 패치 (getCoins=9999, 코드 변조 시연)
    var gc=m.findExportByName('Java_com_mbbypass_mbguarddemo_Guard_getCoins');
    if(gc){ Interceptor.attach(gc,{ onLeave:function(r){ r.replace(9999); } }); Interceptor.flush(); }
    // 3) 패치후 H1 재계산 → 슬롯에 overwrite
    var H1=fnv();
    slot.writeByteArray(toLE(H1));
    console.log('[int] baseline overwrite 완료 H1=0x'+H1.toString(16)+' (patched='+(H0!==H1)+')');
  }catch(e){ console.log('[int err] '+e+'\n'+e.stack); }
})();
