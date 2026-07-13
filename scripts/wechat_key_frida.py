#!/usr/bin/env python3
"""
WeChat macOS database key extractor via Frida.

Hooks CommonCrypto CCKeyDerivationPBKDF (PBKDF2-HMAC-SHA512, high rounds)
which WeChat 4.x calls when opening encrypted databases.

IMPORTANT (macOS sandbox):
  Do NOT frida.spawn() the raw WeChat binary by default. That bypasses
  LaunchServices, so the app may not attach to the sandboxed container
  (~/Library/Containers/com.tencent.xinWeChat/...) and shows an empty /
  "new user" profile without original chat data.

  Default mode is "open": kill → 'open -a WeChat' (correct container) →
  attach ASAP and hook PBKDF2 while auto-login / DB open runs.

Usage:
  python3 scripts/wechat_key_frida.py
  python3 scripts/wechat_key_frida.py --mode open --timeout 180
  python3 scripts/wechat_key_frida.py --mode spawn   # empty profile risk
  python3 scripts/wechat_key_frida.py --mode attach  # already running
  python3 scripts/wechat_key_frida.py --json --timeout 180

Requires: pip3 install frida-tools
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

try:
    import frida
except ImportError:
    print(
        "ERROR: frida is not installed. Run: pip3 install frida-tools",
        file=sys.stderr,
    )
    sys.exit(2)

DEFAULT_WECHAT = "/Applications/WeChat.app/Contents/MacOS/WeChat"
DEFAULT_APP = "/Applications/WeChat.app"
FRIDA_CLEANUP_TIMEOUT = 1.5
FRIDA_SHUTDOWN_TIMEOUT = 1.5
DEFAULT_COLLECTION_WINDOW = 5.0

# Frida 17+ compatible: Module.getGlobalExportByName
JS_HOOK = r"""
'use strict';

function toHex(ptr, len) {
    try {
        if (ptr.isNull() || len <= 0 || len > 256) return null;
        var arr = new Uint8Array(ptr.readByteArray(len));
        var out = '';
        for (var i = 0; i < arr.length; i++) {
            var h = arr[i].toString(16);
            out += (h.length < 2 ? '0' : '') + h;
        }
        return out;
    } catch (e) {
        return null;
    }
}

function tryHook() {
    var pbkdf2 = null;
    try {
        pbkdf2 = Module.getGlobalExportByName('CCKeyDerivationPBKDF');
    } catch (e1) {
        try {
            var mod = Process.getModuleByName('libcommonCrypto.dylib');
            if (mod) pbkdf2 = mod.findExportByName('CCKeyDerivationPBKDF');
        } catch (e2) {}
        if (!pbkdf2) {
            try {
                var mod2 = Process.findModuleByName('libcommonCrypto.dylib');
                if (mod2) pbkdf2 = mod2.findExportByName('CCKeyDerivationPBKDF');
            } catch (e3) {}
        }
    }
    if (!pbkdf2) {
        send({type: 'error', message: 'CCKeyDerivationPBKDF not found'});
        return false;
    }

    Interceptor.attach(pbkdf2, {
        onEnter: function (args) {
            this.algo = args[0].toInt32();
            this.pwdPtr = args[1];
            this.pwdLen = args[2].toInt32();
            this.saltPtr = args[3];
            this.saltLen = args[4].toInt32();
            this.prf = args[5].toInt32();
            this.rounds = args[6].toInt32();
            this.dkPtr = args[7];
            this.dkLen = args[8].toInt32();
            this.interesting =
                this.algo === 2 &&
                this.prf >= 1 && this.prf <= 5 &&
                this.rounds >= 1000 &&
                this.pwdLen > 0 && this.pwdLen <= 64 &&
                this.dkLen > 0 && this.dkLen <= 64;
        },
        onLeave: function (retval) {
            if (!this.interesting) return;
            var pwdHex = toHex(this.pwdPtr, this.pwdLen);
            var saltHex = toHex(this.saltPtr, this.saltLen);
            var dkHex = toHex(this.dkPtr, this.dkLen);
            if (!pwdHex) return;
            send({
                type: 'key',
                key: pwdHex,
                derived_key: dkHex,
                salt: saltHex,
                rounds: this.rounds,
                len: this.pwdLen,
                dk_len: this.dkLen,
                prf: this.prf,
                algo: this.algo
            });
        }
    });
    send({type: 'status', message: 'CCKeyDerivationPBKDF hooked @ ' + pbkdf2});
    return true;
}

if (!tryHook()) {
    var n = 0;
    var t = setInterval(function () {
        n++;
        if (tryHook() || n >= 20) clearInterval(t);
    }, 250);
}
"""


def log(msg: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"type": "log", "message": msg}, ensure_ascii=False), flush=True)
    else:
        print(msg, flush=True)


def emit_error(msg: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"type": "error", "message": msg}, ensure_ascii=False), flush=True)
    else:
        print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def cleanup_frida(script, session, as_json: bool, timeout: float = FRIDA_CLEANUP_TIMEOUT) -> bool:  # noqa: ANN001
    """Unload the hook and detach without allowing Frida cleanup to hang forever."""
    if script is None and session is None:
        return True

    completed = threading.Event()
    cleanup_errors: list[str] = []

    def _cleanup() -> None:
        try:
            if script is not None and not getattr(script, "is_destroyed", False):
                script.unload()
        except Exception as e:  # noqa: BLE001
            cleanup_errors.append(f"script unload failed: {e}")

        try:
            if session is not None and not getattr(session, "is_detached", False):
                session.detach()
        except Exception as e:  # noqa: BLE001
            cleanup_errors.append(f"session detach failed: {e}")
        finally:
            completed.set()

    threading.Thread(target=_cleanup, name="frida-cleanup", daemon=True).start()
    if not completed.wait(max(0.0, timeout)):
        emit_error(
            f"Frida cleanup exceeded {timeout:.1f}s; forcing the injector host to exit",
            as_json,
        )
        return False

    for cleanup_error in cleanup_errors:
        emit_error(cleanup_error, as_json)
    return True


def shutdown_frida_runtime(as_json: bool, timeout: float = FRIDA_SHUTDOWN_TIMEOUT) -> bool:
    """Stop Frida's GLib/device-manager runtime so frida-helper is not orphaned."""
    completed = threading.Event()
    shutdown_errors: list[str] = []

    def _shutdown() -> None:
        try:
            frida.shutdown()
        except Exception as e:  # noqa: BLE001
            shutdown_errors.append(f"Frida runtime shutdown failed: {e}")
        finally:
            completed.set()

    threading.Thread(target=_shutdown, name="frida-runtime-shutdown", daemon=True).start()
    if not completed.wait(max(0.0, timeout)):
        emit_error(
            f"Frida runtime shutdown exceeded {timeout:.1f}s; forcing the injector host to exit",
            as_json,
        )
        return False
    for shutdown_error in shutdown_errors:
        emit_error(shutdown_error, as_json)
    return not shutdown_errors


def find_wechat_pid(exclude: set[int] | None = None) -> int | None:
    """Locate the main WeChat binary PID (not AppEx / helpers)."""
    exclude = exclude or set()
    try:
        out = subprocess.check_output(["/bin/ps", "-A", "-o", "pid=,command="], text=True)
        best = None
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid in exclude:
                continue
            cmd = parts[1]
            if "WeChatAppEx" in cmd or "Helper" in cmd or "crashpad" in cmd:
                continue
            if "WeChat.app/Contents/MacOS/WeChat" in cmd or cmd.endswith("MacOS/WeChat"):
                if best is None or pid > best:
                    best = pid
        if best is not None:
            return best
    except Exception:
        pass

    try:
        device = frida.get_local_device()
        for p in device.enumerate_processes():
            if p.pid in exclude:
                continue
            name = (p.name or "").strip()
            low = name.lower()
            if name == "微信" or low == "wechat":
                return int(p.pid)
    except Exception:
        pass
    return None


def kill_wechat() -> None:
    # Prefer gentle terminate of main binary + helpers
    subprocess.call(["/usr/bin/pkill", "-x", "WeChat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["/usr/bin/killall", "WeChat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Give LaunchServices a moment to release the previous instance
    for _ in range(30):
        if find_wechat_pid() is None:
            break
        time.sleep(0.1)
    time.sleep(0.3)


def resolve_app_bundle(exe: str) -> str:
    exe = os.path.abspath(exe)
    marker = ".app/"
    idx = exe.lower().find(marker)
    if idx > 0:
        return exe[: idx + 4]
    if os.path.isdir(DEFAULT_APP):
        return DEFAULT_APP
    return DEFAULT_APP


def open_wechat_app(app_path: str, as_json: bool) -> None:
    """Launch WeChat via LaunchServices so the sandbox container is correct."""
    # If chatlog/frida is under sudo, open as the real login user so data stays
    # under ~/Library/Containers/... instead of /var/root/...
    sudo_user = (os.environ.get("SUDO_USER") or "").strip()
    euid = os.geteuid() if hasattr(os, "geteuid") else -1

    if euid == 0 and sudo_user and sudo_user != "root":
        cmd = ["sudo", "-u", sudo_user, "/usr/bin/open", "-a", app_path]
        log(f"[*] Launching WeChat as user {sudo_user} (avoid root container): {' '.join(cmd)}", as_json)
    else:
        if euid == 0:
            log(
                "[!] WARNING: running as root without SUDO_USER; WeChat may use "
                "/var/root container (empty profile). Prefer non-root: pip3 install --user frida-tools",
                as_json,
            )
        cmd = ["/usr/bin/open", "-a", app_path]
        log(f"[*] Launching WeChat via LaunchServices: {' '.join(cmd)}", as_json)

    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_for_wechat_pid(timeout: float, exclude: set[int] | None = None) -> int | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = find_wechat_pid(exclude=exclude)
        if pid:
            return pid
        time.sleep(0.05)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract WeChat macOS DB key via Frida")
    ap.add_argument(
        "--mode",
        choices=("open", "spawn", "attach"),
        default="open",
        help="open=LaunchServices+attach (default, keeps user data); "
        "spawn=frida.spawn raw binary (may open empty profile); "
        "attach=attach running process",
    )
    # Back-compat flags
    ap.add_argument("--spawn", action="store_true", help="alias for --mode spawn (discouraged)")
    ap.add_argument("--attach", action="store_true", help="alias for --mode attach")
    ap.add_argument("--exe", default=os.environ.get("WECHAT_EXE", DEFAULT_WECHAT), help="WeChat binary path")
    ap.add_argument("--app", default=os.environ.get("WECHAT_APP", DEFAULT_APP), help="WeChat.app bundle path")
    ap.add_argument("--timeout", type=int, default=180, help="seconds to wait for key (0 = forever)")
    ap.add_argument(
        "--collect-window",
        type=float,
        default=DEFAULT_COLLECTION_WINDOW,
        help="seconds to keep the hook after the first key so per-database keys can be captured",
    )
    ap.add_argument("--json", action="store_true", help="emit JSON lines (for chatlog integration)")
    ap.add_argument("--no-kill", action="store_true", help="do not kill existing WeChat before launch")
    args = ap.parse_args()

    mode = args.mode
    if args.attach:
        mode = "attach"
    elif args.spawn:
        mode = "spawn"

    if mode == "spawn":
        log(
            "[!] mode=spawn starts the raw binary and often loses the sandboxed "
            "user data container (empty WeChat / re-login). Prefer --mode open.",
            args.json,
        )

    captured: list[dict] = []
    capture_signatures: set[tuple[str, str]] = set()
    state = {"stop": False, "first_capture_at": None}

    def on_message(message, data):  # noqa: ANN001
        if message.get("type") == "error":
            desc = message.get("description") or message.get("stack") or str(message)
            emit_error(str(desc), args.json)
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if isinstance(payload, dict) and payload.get("type") == "key":
            key = (payload.get("key") or "").lower()
            if len(key) == 64 and all(c in "0123456789abcdef" for c in key):
                salt = (payload.get("salt") or "").lower()
                signature = (key, salt)
                if signature in capture_signatures:
                    return
                capture_signatures.add(signature)
                captured.append(payload)
                if state["first_capture_at"] is None:
                    state["first_capture_at"] = time.monotonic()
                if args.json:
                    print(
                        json.dumps(
                            {
                                "type": "key",
                                "key": key,
                                "derived_key": (payload.get("derived_key") or "").lower() or None,
                                "salt": salt or None,
                                "rounds": payload.get("rounds"),
                                "len": payload.get("len"),
                                "dk_len": payload.get("dk_len"),
                                "prf": payload.get("prf"),
                                "algo": payload.get("algo"),
                            },
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                else:
                    print(
                        f"\n[!!!] KEY CAPTURED (len={payload.get('len')} rounds={payload.get('rounds')})\n"
                        f"      {key}\n",
                        flush=True,
                    )
            return
        if isinstance(payload, dict) and payload.get("type") in ("status", "error"):
            msg = payload.get("message") or str(payload)
            if payload.get("type") == "error":
                emit_error(msg, args.json)
            else:
                log(f"[+] {msg}", args.json)
            return
        if payload is not None:
            log(str(payload), args.json)

    session = None
    script = None
    pid = None
    exit_code = 1
    try:
        if mode == "spawn":
            if not os.path.isfile(args.exe):
                emit_error(f"WeChat binary not found: {args.exe}", args.json)
                return 1
            if not args.no_kill:
                log("[*] Stopping existing WeChat...", args.json)
                kill_wechat()
            log(f"[*] Spawning WeChat binary (sandbox risk): {args.exe}", args.json)
            pid = frida.spawn([args.exe])
            log("[3/6] 正在挂载微信进程并安装 Frida Hook", args.json)
            session = frida.attach(pid, persist_timeout=0)
            script = session.create_script(JS_HOOK)
            script.on("message", on_message)
            script.load()
            frida.resume(pid)
            log("[4/6] Frida Hook 已安装，等待微信生成数据库密钥", args.json)

        elif mode == "attach":
            pid = find_wechat_pid()
            if not pid:
                emit_error("WeChat process not found (start WeChat or use --mode open)", args.json)
                return 1
            log(f"[3/6] 正在挂载微信进程 pid={pid} 并安装 Frida Hook", args.json)
            session = frida.attach(pid, persist_timeout=0)
            script = session.create_script(JS_HOOK)
            script.on("message", on_message)
            script.load()
            log("[4/6] Frida Hook 已安装，等待微信生成数据库密钥", args.json)

        else:
            # Default: open via LaunchServices then attach ASAP.
            app_path = args.app
            if not os.path.isdir(app_path):
                app_path = resolve_app_bundle(args.exe)
            if not os.path.isdir(app_path):
                emit_error(f"WeChat.app not found: {app_path}", args.json)
                return 1

            old_pids: set[int] = set()
            if not args.no_kill:
                before = find_wechat_pid()
                if before:
                    old_pids.add(before)
                log("[*] Stopping existing WeChat...", args.json)
                kill_wechat()
            else:
                existing = find_wechat_pid()
                if existing:
                    log(f"[3/6] 正在挂载已运行的微信进程 pid={existing} 并安装 Frida Hook", args.json)
                    pid = existing
                    session = frida.attach(pid, persist_timeout=0)
                    script = session.create_script(JS_HOOK)
                    script.on("message", on_message)
                    script.load()
                    log("[4/6] Frida Hook 已安装，请打开聊天以触发数据库密钥", args.json)

            if session is None:
                open_wechat_app(app_path, args.json)
                log("[*] Waiting for WeChat main process...", args.json)
                pid = wait_for_wechat_pid(timeout=20.0, exclude=old_pids)
                if not pid:
                    emit_error("WeChat did not start within 20s after open -a", args.json)
                    return 1
                log(f"[3/6] 正在挂载微信进程 pid={pid} 并安装 Frida Hook", args.json)
                # Retry attach briefly — process may not be injectable on first tick.
                last_err = None
                for _ in range(50):
                    try:
                        session = frida.attach(pid, persist_timeout=0)
                        last_err = None
                        break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        # PID might have been replaced by a newer main process
                        np = find_wechat_pid(exclude=old_pids)
                        if np:
                            pid = np
                        time.sleep(0.05)
                if session is None:
                    emit_error(f"attach failed: {last_err}", args.json)
                    return 1
                script = session.create_script(JS_HOOK)
                script.on("message", on_message)
                script.load()
                log("[4/6] Frida Hook 已安装，等待登录或聊天触发数据库密钥", args.json)

        def _handle_sig(_signum, _frame):  # noqa: ANN001
            state["stop"] = True

        signal.signal(signal.SIGINT, _handle_sig)
        signal.signal(signal.SIGTERM, _handle_sig)

        deadline = None if args.timeout <= 0 else time.time() + args.timeout
        collect_window = max(0.0, float(args.collect_window))
        while not state["stop"]:
            first_capture_at = state["first_capture_at"]
            if first_capture_at is not None and time.monotonic() - first_capture_at >= collect_window:
                break
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(0.2)

        if captured:
            best = captured[0]
            for c in captured:
                if c.get("rounds") == 256000 and c.get("len") == 32:
                    best = c
                    break
            key = (best.get("key") or "").lower()
            if not args.json:
                print(f"[*] Done. data_key={key}", flush=True)
            else:
                unique_keys = len({(c.get("key") or "").lower() for c in captured})
                print(
                    json.dumps(
                        {
                            "type": "done",
                            "key": key,
                            "count": len(captured),
                            "unique_keys": unique_keys,
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            exit_code = 0
            return exit_code

        err = (
            "timeout: no key captured. With --mode open, ensure auto-login completes "
            "or open a chat window; increase --timeout if needed."
        )
        emit_error(err, args.json)
        return exit_code
    except frida.ProcessNotFoundError as e:
        emit_error(f"process not found: {e}", args.json)
        return exit_code
    except frida.PermissionDeniedError as e:
        emit_error(
            f"permission denied (run as the logged-in user, not root if possible): {e}",
            args.json,
        )
        return exit_code
    except Exception as e:  # noqa: BLE001
        emit_error(str(e), args.json)
        return exit_code
    finally:
        cleanup_ok = cleanup_frida(script, session, args.json)
        shutdown_ok = shutdown_frida_runtime(args.json)
        if cleanup_ok and shutdown_ok:
            if args.json:
                print(
                    json.dumps(
                        {
                            "type": "cleanup",
                            "message": "Frida script unloaded, session detached, and runtime shut down.",
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            else:
                log("[*] Frida script unloaded, session detached, and runtime shut down.", args.json)
        # Bypass Frida/Python atexit handlers after the bounded explicit cleanup;
        # some Frida builds otherwise keep a helper-owned stdout pipe alive.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(exit_code)


if __name__ == "__main__":
    sys.exit(main())
