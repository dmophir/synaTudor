#!/usr/bin/env python3
"""
Synaptics Tudor/Augusta plaintext VCSFW command capture (Windows + Frida).

Purpose: on a Windows machine whose 06cb:00bc fingerprint sensor works, hook the
single chokepoint in synaWudfBioUsb103.dll that carries EVERY plaintext VCSFW
command (before TLS wrap) and its reply (after TLS unwrap). Running a real Windows
enroll + verify while this is attached captures the full protocol we can't get
statically: the SAP secure-session handshake, the MIS matcher enroll/verify (0x96/
0x99), and the DB2 template write (pEncryptedTemplate, 0xa2).

Chokepoint (reverse-engineered): the generic VCSFW transceiver.
  Win64 fastcall(rcx=dev, edx=opcode, r8=req_desc, r9=reply_desc)
  req_desc/reply_desc = { uint32 len @ +0x00 ; void* ptr @ +0x08 }
  Located by a unique 24-byte prologue AOB (byte-identical across driver versions),
  so this is robust to the exact DLL build on your machine.

Requirements:
  - Windows, run as ADMINISTRATOR (needed to attach to WUDFHost.exe).
  - Python 3.8+ and Frida:  pip install frida
  - The fingerprint sensor working in Windows (Settings > Sign-in options > Fingerprint).

Usage (elevated cmd/PowerShell):
  python syna_frida_capture.py
Then perform the actions in README.md (remove+add a fingerprint, then verify),
and press Ctrl+C. Send the produced 'syna_capture.log' back.
"""

import sys
import time
import datetime
import argparse

try:
    import frida
except ImportError:
    print("Frida not installed. Run:  pip install frida")
    sys.exit(1)

# Unique prologue of the generic VCSFW transceiver fcn.18008a570 (RVA 0x8a570 in
# synaWudfBioUsb103.dll; byte-identical in the 104 build). No relocated operands ->
# no wildcards. One hit per module.
AOB = "4C 89 4C 24 20 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 81 EC 98 00 00 00"

# Match the Synaptics UMDF USB driver module by name pattern (any version), and as a
# fallback scan every loaded module for the AOB.
JS = r"""
var AOB = "%s";

function tryHookModule(m) {
    var matches;
    try { matches = Memory.scanSync(m.base, m.size, AOB); }
    catch (e) { return false; }
    if (matches.length === 0) return false;
    var target = matches[0].address;
    send({t: "hooked", mod: m.name, path: m.path, base: m.base.toString(),
          rva: target.sub(m.base).toString(), addr: target.toString()});
    Interceptor.attach(target, {
        onEnter: function (args) {
            this.opcode = args[1].toInt32() & 0xff;
            this.reqDesc = args[2];
            this.replyDesc = args[3];
            try {
                var rlen = this.reqDesc.readU32();
                var rptr = this.reqDesc.add(8).readPointer();
                var n = rlen; if (n > 4096) n = 4096;
                var data = (rptr.isNull() || n === 0) ? null : rptr.readByteArray(n);
                send({t: "req", op: this.opcode, len: rlen}, data);
            } catch (e) { send({t: "reqerr", op: this.opcode, e: String(e)}); }
        },
        onLeave: function (retval) {
            try {
                var plen = this.replyDesc.readU32();
                var pptr = this.replyDesc.add(8).readPointer();
                var n = plen; if (n > 8192) n = 8192;
                var data = (pptr.isNull() || n === 0) ? null : pptr.readByteArray(n);
                send({t: "rep", op: this.opcode, len: plen, ret: retval.toInt32()}, data);
            } catch (e) { send({t: "reperr", op: this.opcode, e: String(e)}); }
        }
    });
    return true;
}

function main() {
    var hooked = false;
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (/synaWudfBioUsb.*\.dll/i.test(mods[i].name)) {
            if (tryHookModule(mods[i])) { hooked = true; }
        }
    }
    if (!hooked) {
        for (var j = 0; j < mods.length; j++) {
            if (tryHookModule(mods[j])) { hooked = true; break; }
        }
    }
    if (!hooked) send({t: "nomatch", count: mods.length});
}
main();
""" % AOB


def hexs(data):
    return data.hex() if data else ""


def make_handler(pid, logf):
    def on_message(message, data):
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if message.get("type") == "error":
            line = "[%s] PID=%d FRIDA-ERROR %s" % (ts, pid, message.get("description", message))
            print(line); logf.write(line + "\n"); logf.flush(); return
        p = message.get("payload", {})
        t = p.get("t")
        if t == "hooked":
            line = ("[%s] PID=%d HOOKED mod=%s rva=%s base=%s\n            path=%s"
                    % (ts, pid, p.get("mod"), p.get("rva"), p.get("base"), p.get("path")))
            print(line); logf.write(line + "\n"); logf.flush()
        elif t == "req":
            line = "[%s] PID=%d REQ op=0x%02x len=%d\n  %s" % (ts, pid, p["op"], p["len"], hexs(data))
            logf.write(line + "\n"); logf.flush()
            print("[%s] REQ op=0x%02x len=%d" % (ts, p["op"], p["len"]))
        elif t == "rep":
            line = "[%s] PID=%d REP op=0x%02x len=%d ret=%d\n  %s" % (ts, pid, p["op"], p["len"], p.get("ret", 0), hexs(data))
            logf.write(line + "\n"); logf.flush()
            print("[%s] REP op=0x%02x len=%d ret=%d" % (ts, p["op"], p["len"], p.get("ret", 0)))
        elif t in ("reqerr", "reperr"):
            line = "[%s] PID=%d %s op=0x%02x err=%s" % (ts, pid, t.upper(), p.get("op", 0), p.get("e"))
            print(line); logf.write(line + "\n"); logf.flush()
        elif t == "nomatch":
            print("[%s] PID=%d no synaWudfBioUsb module / AOB (scanned %d modules)" % (ts, pid, p.get("count", 0)))
        else:
            logf.write("[%s] PID=%d MSG %r\n" % (ts, pid, message)); logf.flush()
    return on_message


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="syna_capture.log")
    ap.add_argument("--proc", default="WUDFHost.exe",
                    help="process name that hosts the UMDF driver (default WUDFHost.exe)")
    ap.add_argument("--seconds", type=int, default=0,
                    help="auto-stop after N seconds (0 = run until Ctrl+C)")
    args = ap.parse_args()

    device = frida.get_local_device()
    procs = [p for p in device.enumerate_processes() if p.name.lower() == args.proc.lower()]
    if not procs:
        print("No %s processes found. Is the sensor present/working in Windows?" % args.proc)
        sys.exit(2)

    logf = open(args.log, "w", encoding="utf-8")
    logf.write("# syna VCSFW plaintext capture  started %s\n"
               % datetime.datetime.now().isoformat())
    logf.flush()

    sessions = []
    print("Found %d %s process(es): %s" % (len(procs), args.proc, [p.pid for p in procs]))
    for p in procs:
        try:
            session = device.attach(p.pid)
            script = session.create_script(JS)
            script.on("message", make_handler(p.pid, logf))
            script.load()
            sessions.append((session, script))
            print("  attached + injected into PID %d" % p.pid)
        except Exception as e:
            print("  could not attach PID %d: %r" % (p.pid, e))

    if not sessions:
        print("Could not attach to any WUDFHost. Are you running as Administrator?")
        sys.exit(3)

    print("\n>>> Hooks loaded. Look for a 'HOOKED mod=synaWudfBioUsb...' line above.")
    print(">>> Now: (1) remove + add a fingerprint in Windows Settings, (2) verify with it.")
    if args.seconds and args.seconds > 0:
        print(">>> Auto-stopping after %d seconds.\n" % args.seconds)
    else:
        print(">>> Press Ctrl+C when done.\n")
    try:
        if args.seconds and args.seconds > 0:
            time.sleep(args.seconds)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for session, script in sessions:
            try: script.unload()
            except Exception: pass
            try: session.detach()
            except Exception: pass
        logf.write("# capture ended %s\n" % datetime.datetime.now().isoformat())
        logf.close()
        print("\nSaved capture to %s" % args.log)


if __name__ == "__main__":
    main()
