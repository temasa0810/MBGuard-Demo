# florida(-H) 원격으로 L3 데모를 spawn하고 dump_lv2.js를 로드해 복호 순간 평문 ELF를 덤프한다.
import frida, sys, time

PKG = "com.mbbypass.mbguarddemo.l3"
dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid = dev.spawn([PKG])
sess = dev.attach(pid)
with open("dump_lv2.js", "r", encoding="utf-8") as f:
    src = f.read()
sc = sess.create_script(src)
sc.on("message", lambda m, d: print("[msg]", m.get("payload") if m.get("type") == "send" or m.get("type") == "log" else m))
sc.load()
dev.resume(pid)
time.sleep(6)
print("[driver] done, pid=", pid)
