import subprocess
import sys
import ctypes
import os

def _ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        print("\n  Pas administrateur — relance avec élévation...", flush=True)
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas",
                sys.executable,
                " ".join(f'"{a}"' for a in sys.argv),
                None, 1
            )
        except Exception as e:
            print(f"  Élévation impossible : {e}", flush=True)
            input("  Appuie sur Entrée pour continuer sans admin (certaines fonctions désactivées)...")
        sys.exit(0)

_ensure_admin()

def install_deps():
    pkgs = ["pefile", "yara-python", "colorama"]
    for pkg in pkgs:
        mod = pkg.replace("-python", "").replace("-", "_")
        try:
            __import__(mod)
        except ImportError:
            print(f"  Installation de {pkg}...", flush=True)
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

print("\n  Veuillez patienter — préparation des dépendances...", flush=True)
install_deps()
print("  Dépendances prêtes.\n", flush=True)

import re
import json
import mmap
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

from colorama import init, Fore, Style
init(autoreset=True)
RED    = Fore.RED
YELLOW = Fore.YELLOW
GREEN  = Fore.GREEN
CYAN   = Fore.CYAN
BOLD   = Style.BRIGHT
RESET  = Style.RESET_ALL
DIM    = Style.DIM

C2_DOMAINS = [
    "i-like.boats", "powercat.dog", "devruntime.cy", "zetolacs-cloud.top",
    "frozi.cc", "exo-api.tf", "nuzzyservices.com", "darkside.cy",
    "balista.lol", "phobos.top", "phobosransom.com", "pee-files.nl",
    "vcc-library.uk", "luckyware.co", "luckyware.cc", "luckyware.pw",
    "dhszo.darkside.cy", "risesmp.net", "luckystrike.pw", "krispykreme.top",
    "vcc-redistrbutable.help", "i-slept-with-ur.mom", "luckyware.queenmc.pl",
    "lumma.cy", "www.lumma.cy",
]

C2_URLS = [
    "https://lumma.cy/sixxlerrr",
    "http://lumma.cy/sixxlerrr",
]

C2_IPS = ["91.92.243.218", "188.114.96.11"]

MALICIOUS_PROCESSES = [
    "Berok.exe", "Retev.exe", "Zetolac.exe", "HPSR.exe",
    "Lumma.exe", "LummaC2.exe", "LummaStealer.exe", "Stealer.exe",
]

# ── Infostealer : vol de cookies / tokens / sessions ───────────────────────
STEALER_NAME_RE = re.compile(
    r'(?i)(lumma|stealer|sixxlerrr|grabber|token|cookie|session|wallet)'
)
STEALER_STRONG_RE = re.compile(r'(?i)(lumma|stealer|grabber|sixxlerrr)')

BROWSER_STAGING_NAMES = {
    "cookies", "cookies.sqlite", "login data", "local state",
    "key4.db", "key3.db", "logins.json", "key5.db",
}

CHROMIUM_BROWSERS = [
    "Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave-Browser",
    "Opera Software\\Opera Stable", "Vivaldi", "Chromium", "Yandex\\YandexBrowser",
]

SUSPICIOUS_EXT_PERMS = {
    "<all_urls>", "cookies", "webrequest", "webrequestblocking", "debugger",
}

PE_NORMAL_SECTIONS = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".edata",
    ".idata", ".tls", ".bss", ".rcdata", ".gfids", ".giats", ".00cfg",
}

PE_SUSPICIOUS_APIS = (
    b"WriteProcessMemory", b"CreateRemoteThread", b"VirtualAllocEx",
    b"WinHttpOpen", b"URLDownloadToFile", b"InternetOpenUrl",
    b"SetWindowsHookEx",
)

IMGUI_HEX_BLOB    = re.compile(rb'std::string\s+F[a-zA-Z0-9]{5,}\s*=\s*"(\\x[0-9a-fA-F]{2}){20,}"')
IMGUI_SYSTEM_CALL = re.compile(rb'\bsystem\s*\(\s*[A-Za-z_]')

VCXPROJ_PATTERNS = [
    (re.compile(rb'powershell\s+-WindowStyle\s+Hidden', re.IGNORECASE), "hidden powershell"),
    (re.compile(rb'iwr\s+-Uri',                         re.IGNORECASE), "iwr download"),
    (re.compile(rb'cmd\.exe\s+/b\s+/c',                re.IGNORECASE), "cmd /b /c"),
    (re.compile(rb'cmd\.exe\s+/c\s+/b',                re.IGNORECASE), "cmd /c /b"),
    (re.compile(rb'Invoke-WebRequest',                  re.IGNORECASE), "Invoke-WebRequest"),
]

VCXPROJ_QUICKCHECK = (b"powershell", b"iwr", b"cmd.exe", b"invoke-webrequest")

SDK_PATTERN = re.compile(
    rb'namespace\s+VccLibaries|namespace\s+SDKInfector|'
    rb'Bombakla|Rundollay|InfectSDK|InfectINIT',
    re.IGNORECASE
)

SDK_STRINGS_DISPLAY = {
    b"namespace vcclibar":  "namespace VccLibaries",
    b"namespace sdkinfect": "namespace SDKInfector",
    b"bombakla":            "Bombakla",
    b"rundollay":           "Rundollay",
    b"infectsdk":           "InfectSDK",
    b"infectinit":          "InfectINIT",
}

TEMP_FILE_RE = re.compile(r'^[A-Z]{2,3}\d{10,13}(\.exe)?$')

TEXT_INDICATOR_EXTENSIONS = {
    ".js", ".vbs", ".ps1", ".bat", ".cmd", ".reg",
    ".json", ".ini", ".url", ".lnk", ".xml", ".htm", ".html",
}

TARGET_EXTENSIONS = {
    ".exe", ".dll",
    ".vcxproj", ".csproj",
    ".suo",
    ".h", ".hpp", ".cpp",
} | TEXT_INDICATOR_EXTENSIONS

IMGUI_FILENAMES_SET = {
    "imgui_impl_win32.cpp",
    "imgui_impl_win32.h",
    "imgui.cpp",
    "imgui_widgets.cpp",
    "imgui_draw.cpp",
}

SKIP_DIRS = {
    "quarantine", "luckykiller", ".git", "node_modules",
    "__pycache__", ".vs",
}

SKIP_PATH_FRAGMENTS = (
    "\\windows kits\\",
    "\\microsoft visual studio\\",
    "\\qt\\tools\\",
    "\\qt\\examples\\",
    "\\pyside",
    "\\luau\\cli\\",
)

XOR_KEY_BYTES = b"NtExploreProcess"
MZ_MAGIC      = b"MZ"
PE_MIN_SIZE   = 64
MMAP_THRESH   = 512 * 1024


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input(f"\n  {DIM}Appuie sur Entrée pour revenir au menu...{RESET}")


def fmt_eta(seconds):
    if seconds <= 0 or seconds > 86400:
        return "--:--"
    return str(timedelta(seconds=int(seconds)))[2:]


def _read_file(path, size):
    if size == 0:
        return b""
    if size > MMAP_THRESH:
        try:
            with open(path, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                data = mm[:]
                mm.close()
            return data
        except Exception:
            pass
    with open(path, "rb") as f:
        return f.read()


class Threat:
    __slots__ = ("path", "reason", "action_taken", "_printed")

    def __init__(self, path, reason):
        self.path         = path
        self.reason       = reason
        self.action_taken = "aucune"
        self._printed     = False


class LuckyKiller:
    def __init__(self, scan_roots, auto_remove=True, block=True, workers=0):
        self.scan_roots  = scan_roots
        self.auto_remove = auto_remove
        self.block       = block
        self.workers     = workers or (os.cpu_count() or 4) * 4

        self.threats         = []
        self._lock           = threading.Lock()
        self._files_scanned  = 0
        self._start_time     = 0.0
        self._yara_rules     = None
        self._pending_logs   = []

        if HAS_YARA:
            self._compile_yara()

    def _compile_yara(self):
        src = r"""
rule Luckyware_C2 {
    strings:
        $d1="devruntime.cy" nocase $d2="zetolacs-cloud.top" nocase
        $d3="frozi.cc" nocase $d4="exo-api.tf" nocase
        $d5="nuzzyservices.com" nocase $d6="darkside.cy" nocase
        $d7="balista.lol" nocase $d8="phobos.top" nocase
        $d9="vcc-library.uk" nocase $d10="luckyware.co" nocase
        $d11="luckyware.cc" nocase $d12="91.92.243.218" nocase
        $d13="188.114.96.11" nocase $d14="risesmp.net" nocase
        $d15="luckystrike.pw" nocase $d16="krispykreme.top" nocase
        $d17="i-slept-with-ur.mom" nocase $d18="vcc-redistrbutable.help" nocase
        $d19="lumma.cy" nocase $d20="sixxlerrr" nocase
    condition: any of them
}
rule Luckyware_XOR_Key {
    strings: $k = "NtExploreProcess"
    condition: $k
}
rule Luckyware_SDK {
    strings:
        $ns1 = "namespace VccLibaries" nocase
        $ns2 = "namespace SDKInfector" nocase
        $f1 = "Bombakla" nocase $f2 = "Rundollay" nocase
        $f3 = "InfectSDK" nocase $f4 = "InfectINIT" nocase
    condition: any of them
}
rule Luckyware_BuildEvent {
    strings:
        $ps  = "powershell -WindowStyle Hidden" nocase
        $iwr = "iwr -Uri" nocase
        $cmd = "cmd.exe /b /c" nocase
    condition: any of them
}
rule Luckyware_ImGui {
    strings:
        $h = /std::string F[a-zA-Z0-9]{5,}\s*=\s*"(\\x[0-9a-fA-F]{2}){20,}"/
    condition: $h
}
rule Lumma_Infostealer {
    strings:
        $a = "lumma.cy" nocase
        $b = "sixxlerrr" nocase
        $c = "LummaC2" nocase
        $d = "lumma" nocase
    condition: any of ($a,$b,$c) or (2 of ($a,$d))
}
rule Token_Cookie_Theft {
    strings:
        $c1 = "cookies.sqlite" nocase
        $c2 = "Login Data" nocase
        $c3 = "Local State" nocase
        $c4 = "logins.json" nocase
        $c5 = "key4.db" nocase
        $c6 = "wallet.dat" nocase
        $x1 = "api.telegram.org/bot" nocase
        $x2 = "discord.com/api/webhooks" nocase
        $x3 = "discordapp.com/api/webhooks" nocase
    condition: (2 of ($c*)) or any of ($x*)
}
rule Lumma_Session_Exfil {
    strings:
        $s1 = "session" nocase
        $s2 = "token" nocase
        $s3 = "cookie" nocase
        $s4 = "steal" nocase
        $u1 = "https://" nocase
    condition: $s4 and (2 of ($s1,$s2,$s3)) and $u1
}
"""
        try:
            self._yara_rules = yara.compile(source=src)
        except Exception as e:
            self._ilog("WARN", f"Échec de compilation YARA : {e}")

    def _fmt_line(self, level, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        icons = {
            "FOUND": f"{RED}[!]{RESET}",
            "CLEAN": f"{GREEN}[+]{RESET}",
            "INFO":  f"{CYAN}[*]{RESET}",
            "WARN":  f"{YELLOW}[~]{RESET}",
            "ACT":   f"{BOLD}{YELLOW}[>]{RESET}",
        }
        return f"  {icons.get(level, '[?]')} [{ts}] {msg}"

    def _ilog(self, level, msg):
        print(self._fmt_line(level, msg))

    def _qlog(self, level, msg):
        with self._lock:
            self._pending_logs.append(self._fmt_line(level, msg))

    def _flush_logs(self):
        with self._lock:
            lines = self._pending_logs[:]
            self._pending_logs.clear()
        for line in lines:
            print(line)

    def _add_threat(self, path, reason):
        t = Threat(path, reason)
        with self._lock:
            self.threats.append(t)
        return t

    def _is_noisy_path(self, path_lower):
        return path_lower.startswith(SKIP_PATH_FRAGMENTS) or \
               any(frag in path_lower for frag in SKIP_PATH_FRAGMENTS)

    @staticmethod
    def _shallow_entries(root, max_depth=3, skip_dirs=SKIP_DIRS):
        """Parcours borné en profondeur (TEMP / APPDATA / Bureau)."""
        front = [(root, 0)]
        while front:
            cur, depth = front.pop()
            try:
                with os.scandir(cur) as it:
                    entries = list(it)
            except OSError:
                continue
            for e in entries:
                try:
                    is_dir = e.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                if is_dir:
                    if depth < max_depth and e.name.lower() not in skip_dirs:
                        front.append((e.path, depth + 1))
                else:
                    yield e

    def _browser_roots(self):
        roots = set()
        local   = os.environ.get("LOCALAPPDATA")
        roaming = os.environ.get("APPDATA")
        public  = os.environ.get("PUBLIC", r"C:\Users\Public")
        if local:
            for browser in CHROMIUM_BROWSERS:
                roots.add(os.path.join(local, browser.replace("\\", os.sep), "User Data"))
            roots.add(os.path.join(local, "Temp"))
        if roaming:
            roots.add(os.path.join(roaming, "Mozilla", "Firefox", "Profiles"))
            roots.add(roaming)
        roots.add(os.path.join(public, "Desktop"))
        for env in ("TEMP", "TMP"):
            val = os.environ.get(env)
            if val:
                roots.add(val)
        return [r for r in sorted(roots) if os.path.isdir(r)]

    @staticmethod
    def _looks_like_browser_profile(path_lower):
        return (
            ("user data" in path_lower and
             ("default" in path_lower or "profile " in path_lower))
            or ("profiles" in path_lower and "release" in path_lower)
        )

    @staticmethod
    def _is_temp_dropper_name(name):
        low = name.lower()
        if TEMP_FILE_RE.match(name):
            return True
        return bool(
            STEALER_NAME_RE.search(low)
            and low.endswith((".exe", ".dll", ".scr", ".js", ".vbs",
                              ".ps1", ".bat", ".cmd", ".bin", ".zip", ".rar"))
        )

    def _scan_browser_staging(self):
        """Repère les copies de bases de cookies/tokens hors profils navigateur."""
        self._ilog("INFO", "Recherche de copies de cookies/tokens (staging infostealer)...")
        temp_roots = set()
        for env in ("TEMP", "TMP"):
            val = os.environ.get(env)
            if val:
                temp_roots.add(os.path.abspath(val).lower())
        local  = os.environ.get("LOCALAPPDATA")
        public = os.environ.get("PUBLIC", r"C:\Users\Public")
        if local:
            temp_roots.add(os.path.join(local, "Temp").lower())
        temp_roots.add(os.path.join(public, "Desktop").lower())

        for root in self._browser_roots():
            for e in self._shallow_entries(root, max_depth=4):
                try:
                    low      = e.name.lower()
                    base     = os.path.splitext(low)[0].strip()
                    path_low = e.path.lower()
                    in_temp  = any(path_low.startswith(r) for r in temp_roots)
                    db_like  = (
                        low in BROWSER_STAGING_NAMES
                        or (base in BROWSER_STAGING_NAMES
                            and low.endswith((".db", ".sqlite", ".json",
                                              ".txt", ".bin", ".dat")))
                    )
                    suspicious = (
                        bool(STEALER_STRONG_RE.search(low))
                        or (db_like and in_temp)
                        or (bool(STEALER_NAME_RE.search(low))
                            and low.endswith((".exe", ".dll", ".bin",
                                              ".zip", ".7z", ".rar", ".dat")))
                    )
                    if not suspicious or self._looks_like_browser_profile(e.path.lower()):
                        continue
                    t = self._add_threat(
                        e.path, "Vol de tokens/cookies : fichier de staging infostealer"
                    )
                    if self.auto_remove:
                        self._wipe_file(t)
                except Exception:
                    pass
        self._flush_logs()

    def _scan_browser_extensions(self):
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            return
        self._ilog("INFO", "Vérification des extensions de navigateur...")
        for browser in CHROMIUM_BROWSERS:
            base = os.path.join(local, browser.replace("\\", os.sep), "User Data")
            if not os.path.isdir(base):
                continue
            try:
                profiles = list(os.scandir(base))
            except OSError:
                continue
            for profile in profiles:
                if not profile.is_dir(follow_symlinks=False):
                    continue
                ext_root = os.path.join(profile.path, "Extensions")
                if not os.path.isdir(ext_root):
                    continue
                try:
                    exts = list(os.scandir(ext_root))
                except OSError:
                    continue
                for ext in exts:
                    if ext.is_dir(follow_symlinks=False):
                        self._inspect_extension(ext.path, ext.name, profile.path)
        self._flush_logs()

    def _inspect_extension(self, ext_dir, ext_id, profile):
        try:
            manifests = []
            root_manifest = os.path.join(ext_dir, "manifest.json")
            if os.path.isfile(root_manifest):
                manifests.append(root_manifest)
            for sub in os.scandir(ext_dir):
                if sub.is_dir(follow_symlinks=False):
                    m = os.path.join(sub.path, "manifest.json")
                    if os.path.isfile(m):
                        manifests.append(m)

            raws = []
            for m in manifests:
                try:
                    with open(m, "rb") as f:
                        raws.append(f.read())
                except OSError:
                    continue

            reason = None
            high_confidence = False
            # 1) Référence C2 / clé XOR : signature forte, quarantaine automatique.
            for raw in raws:
                low = raw.lower()
                if (b"lumma.cy" in low or b"sixxlerrr" in low
                        or b"ntexploreprocess" in low):
                    reason = "référence C2 / clé XOR dans le manifeste"
                    high_confidence = True
                    break

            # 2) Cumul de permissions sensibles : simple signalement (faux positifs
            #    possibles sur des extensions légitimes type gestionnaire de mots de passe).
            if not reason:
                for raw in raws:
                    try:
                        manifest = json.loads(raw.decode("utf-8", errors="ignore"))
                    except Exception:
                        continue
                    perms = {str(p).lower() for p in manifest.get("permissions", [])}
                    dangerous = perms & SUSPICIOUS_EXT_PERMS
                    if len(dangerous) >= 2:
                        reason = "permissions sensibles : " + ", ".join(sorted(dangerous))
                        break

            if not reason:
                return
            t = self._add_threat(
                ext_dir, f"Extension navigateur malveillante ({ext_id}) : {reason}"
            )
            if self.auto_remove:
                if high_confidence:
                    self._quarantine_extension(t, ext_dir, ext_id, profile)
                else:
                    t.action_taken = "à vérifier manuellement (permissions sensibles)"
        except Exception:
            pass

    def _quarantine_extension(self, t, ext_dir, ext_id, profile):
        try:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest  = ext_dir + f".LUCKYKILLER_QUARANTINE_{stamp}"
            os.rename(ext_dir, dest)
            actions = [f"extension déplacée → {os.path.basename(dest)}"]

            pref = os.path.join(profile, "Preferences")
            if os.path.isfile(pref):
                try:
                    with open(pref, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    settings = data.get("extensions", {}).get("settings", {})
                    if ext_id in settings:
                        settings[ext_id]["state"] = 0
                        with open(pref + ".luckykiller.bak", "w", encoding="utf-8") as b:
                            json.dump(data, b)
                        with open(pref, "w", encoding="utf-8") as f:
                            json.dump(data, f)
                        actions.append("désactivée dans Preferences (sauvegarde .bak)")
                except Exception:
                    pass
            t.action_taken = "; ".join(actions)
            self._qlog("ACT", f"EXTENSION NEUTRALISÉE : {ext_dir}")
        except Exception as e:
            t.action_taken = f"échec quarantaine extension : {e}"

    def _scan_browser_shortcuts(self):
        """Détecte les raccourcis navigateur détournés (--load-extension, etc.)."""
        roots = []
        appdata = os.environ.get("APPDATA")
        public  = os.environ.get("PUBLIC", r"C:\Users\Public")
        if appdata:
            roots.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu"))
        roots.append(os.path.join(public, "Desktop"))
        roots.append(os.path.join(public, "Documents"))

        needles = (b"--load-extension", b"--disable-web-security", b"--no-sandbox",
                   b"lumma.cy", b"sixxlerrr", b"remote-debugging-port")
        for root in roots:
            if not os.path.isdir(root):
                continue
            for e in self._shallow_entries(root, max_depth=4):
                if not e.name.lower().endswith(".lnk"):
                    continue
                try:
                    with open(e.path, "rb") as f:
                        raw = f.read()
                except OSError:
                    continue
                low  = raw.lower()
                wide = raw.decode("utf-16-le", errors="ignore").lower()
                hits = []
                for n in needles:
                    text = n.decode()
                    if n in low or text in wide:
                        hits.append(text)
                if hits:
                    self._add_threat(
                        e.path, "Raccourci navigateur détourné : " + ", ".join(hits)
                    )
        self._flush_logs()

    def _scan_registry_persistence(self):
        if os.name != "nt":
            return
        try:
            import winreg
        except ImportError:
            return
        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, path in keys:
            try:
                with winreg.OpenKey(hive, path) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        low = f"{name} {value}".lower()
                        if (any(d in low for d in C2_DOMAINS)
                                or STEALER_STRONG_RE.search(low)):
                            self._add_threat(
                                f"REGISTRE\\{path}\\{name}",
                                "Persistance infostealer dans Run/RunOnce"
                            )
            except OSError:
                pass

    def _scan_indicators(self, path, size):
        """Signatures textuelles (scripts, configs, raccourcis) — C2 + exfil."""
        if size == 0:
            return
        try:
            data = _read_file(path, size)
            low  = data.lower()
            hits = []
            for d in C2_DOMAINS:
                if d.encode() in low:
                    hits.append(d)
            for u in C2_URLS:
                if u.encode() in low:
                    hits.append(u)
            if b"sixxlerrr" in low:
                hits.append("sixxlerrr")
            if b"api.telegram.org/bot" in low:
                hits.append("exfil Telegram")
            if b"discord" in low and b"webhook" in low:
                hits.append("exfil Discord")
            if hits:
                self._add_threat(path, "Indicateur de vol : " + ", ".join(sorted(set(hits))))
        except Exception:
            pass

    def _wipe_file(self, t):
        try:
            size = os.path.getsize(t.path)
            with open(t.path, "wb") as f:
                f.write(b"\x00" * size)
            os.remove(t.path)
            t.action_taken = "effacé puis supprimé"
            self._qlog("ACT", f"EFFACÉ : {t.path}")
        except Exception as e:
            t.action_taken = f"échec de l'effacement : {e}"

    def _clean_vcxproj(self, t):
        try:
            with open(t.path, "rb") as f:
                raw = f.read()
            lines   = raw.split(b"\n")
            cleaned = [l for l in lines
                       if not any(p.search(l) for p, _ in VCXPROJ_PATTERNS)]
            if len(cleaned) != len(lines):
                with open(t.path, "wb") as f:
                    f.write(b"\n".join(cleaned))
                n = len(lines) - len(cleaned)
                t.action_taken = f"nettoyé ({n} lignes malveillantes supprimées)"
                self._qlog("ACT", f"VCXPROJ NETTOYÉ ({n} lignes) : {t.path}")
            else:
                t.action_taken = "aucune modification nécessaire"
        except Exception as e:
            t.action_taken = f"échec du nettoyage : {e}"

    def _patch_pe(self, t):
        if not HAS_PEFILE:
            t.action_taken = "pefile non installé"
            return
        try:
            pe      = pefile.PE(t.path)
            patched = False
            for sec in pe.sections:
                name = sec.Name.decode(errors="replace").strip("\x00")
                if name.startswith(".rcd") and name != ".rcdata":
                    if sec.Characteristics & 0x20000000:
                        sec.Characteristics &= ~0x20000000
                        patched = True
            if patched:
                pe.write(t.path)
                t.action_taken = "PE patché (bits d'exécution retirés)"
                self._qlog("ACT", f"PE PATCHÉ : {t.path}")
            pe.close()
        except Exception as e:
            t.action_taken = f"échec du patch : {e}"

    def _kill_process(self, name):
        try:
            r = subprocess.run(["taskkill", "/F", "/IM", name],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                self._ilog("ACT", f"Processus tué : {name}")
        except Exception:
            pass

    def _clean_imgui(self, t):
        try:
            with open(t.path, "rb") as f:
                raw = f.read()
            cleaned = IMGUI_HEX_BLOB.sub(b"/* LUCKYKILLER_REMOVED */", raw)
            cleaned = IMGUI_SYSTEM_CALL.sub(b"/* LUCKYKILLER_REMOVED */", cleaned)
            if cleaned != raw:
                with open(t.path, "wb") as f:
                    f.write(cleaned)
                t.action_taken = "imgui nettoyé"
                self._qlog("ACT", f"IMGUI NETTOYÉ : {t.path}")
            else:
                t.action_taken = "aucune modification faite"
        except Exception as e:
            t.action_taken = f"échec du nettoyage : {e}"

    def _remove_sdk_injection(self, t, matched_lower):
        try:
            with open(t.path, "rb") as f:
                lines = f.readlines()
            cleaned = [l for l in lines if matched_lower not in l.lower()]
            if len(cleaned) != len(lines):
                with open(t.path, "wb") as f:
                    f.writelines(cleaned)
                t.action_taken = "ligne d'injection SDK supprimée"
                self._qlog("ACT", f"SDK NETTOYÉ : {t.path}")
        except Exception as e:
            t.action_taken = f"échec du nettoyage SDK : {e}"

    def _scan_pe(self, path, size):
        if not HAS_PEFILE or size < PE_MIN_SIZE:
            return
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
            if magic != MZ_MAGIC:
                return

            pe = pefile.PE(path, fast_load=True)
            score   = 0
            reasons = []
            for sec in pe.sections:
                name       = sec.Name.decode(errors="replace").strip("\x00")
                entropy    = sec.get_entropy()
                executable = bool(sec.Characteristics & 0x20000000)
                if name.startswith(".rcd") and name != ".rcdata":
                    score += 3
                    reasons.append(
                        f"section malveillante '{name}' entropie={entropy:.2f} exec={executable}"
                    )
                elif (executable and entropy > 7.2
                      and name.lower() not in PE_NORMAL_SECTIONS):
                    score += 2
                    reasons.append(
                        f"section exécutable à forte entropie '{name}' ({entropy:.2f})"
                    )

            raw      = pe.__data__
            mz_count = raw.count(MZ_MAGIC)
            if mz_count > 1:
                score += 3
                reasons.append(f"{mz_count} en-têtes MZ (dropper)")

            if any(api in raw for api in PE_SUSPICIOUS_APIS):
                score += 1
                reasons.append("API d'injection / téléchargement présentes")

            if score >= 3:
                t = self._add_threat(path, "Infection PE: " + "; ".join(reasons))
                if self.auto_remove:
                    self._patch_pe(t)
            pe.close()
        except Exception:
            pass

    def _scan_vcxproj(self, path, size):
        if size == 0:
            return
        try:
            data      = _read_file(path, size)
            data_low  = data.lower()
            if not any(kw in data_low for kw in VCXPROJ_QUICKCHECK):
                return
            hits = [label for pat, label in VCXPROJ_PATTERNS if pat.search(data)]
            if hits:
                t = self._add_threat(path, f"Infection VCXPROJ: {', '.join(hits)}")
                if self.auto_remove:
                    self._clean_vcxproj(t)
        except Exception:
            pass

    def _scan_suo(self, path, size):
        if size == 0:
            return
        try:
            with open(path, "rb") as f:
                chunk = f.read(min(4096, size))
            if XOR_KEY_BYTES in chunk:
                t = self._add_threat(path, "Détournement SUO: clé XOR trouvée dans le fichier .suo")
                if self.auto_remove:
                    self._wipe_file(t)
        except Exception:
            pass

    def _scan_imgui(self, path, size, path_lower):
        if size == 0:
            return
        try:
            data = _read_file(path, size)

            has_xor  = XOR_KEY_BYTES in data
            has_blob = b"std::string" in data and bool(IMGUI_HEX_BLOB.search(data))

            if not (has_xor or has_blob):
                return

            has_system = bool(IMGUI_SYSTEM_CALL.search(data))

            if has_blob and (has_system or has_xor):
                parts = ["blob hex obfusqué"]
                if has_xor:
                    parts.append("clé XOR")
                if has_system:
                    parts.append("appel dropper system()")
                t = self._add_threat(path, f"Infection ImGui: {' + '.join(parts)}")
                if self.auto_remove:
                    self._clean_imgui(t)
            elif has_xor and not self._is_noisy_path(path_lower):
                t = self._add_threat(path, "Infection source: clé XOR NtExploreProcess trouvée")
                if self.auto_remove:
                    self._clean_imgui(t)
        except Exception:
            pass

    def _scan_sdk_header(self, path, size, path_lower):
        if size == 0:
            return
        try:
            data = _read_file(path, size)
            m    = SDK_PATTERN.search(data)
            if not m:
                return
            matched_lower = m.group(0).lower()
            display = matched_lower.decode(errors="replace")
            for key, label in SDK_STRINGS_DISPLAY.items():
                if matched_lower.startswith(key):
                    display = label
                    break
            t = self._add_threat(path, f"Empoisonnement SDK: '{display}' injecté dans l'en-tête")
            if self.auto_remove:
                self._remove_sdk_injection(t, matched_lower)
        except Exception:
            pass

    def _scan_yara(self, path):
        if not self._yara_rules:
            return
        try:
            matches = self._yara_rules.match(path)
            for m in matches:
                self._add_threat(path, f"YARA: {m.rule}")
        except Exception:
            pass

    def _scan_temp_dirs(self):
        dirs = set()
        for env in ("TEMP", "TMP"):
            val = os.environ.get(env)
            if val:
                dirs.add(val)
        local = os.environ.get("LOCALAPPDATA")
        if local:
            dirs.add(os.path.join(local, "Temp"))
        roaming = os.environ.get("APPDATA")
        if roaming:
            dirs.add(roaming)

        for d in dirs:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.scandir(d):
                    if (entry.is_file(follow_symlinks=False)
                            and self._is_temp_dropper_name(entry.name)):
                        t = self._add_threat(
                            entry.path, "Dropper Temp: fichier Luckyware / infostealer"
                        )
                        if self.auto_remove:
                            self._wipe_file(t)
            except Exception:
                pass

    def _scan_windows_sdk(self):
        roots = []
        for base in [r"C:\Program Files (x86)\Windows Kits",
                     r"C:\Program Files\Windows Kits"]:
            if os.path.isdir(base):
                roots.append(base)
        if not roots:
            return

        tasks = []
        for root in roots:
            for entry in _fast_walk(root, skip_dirs=set()):
                if entry.name.endswith((".h", ".hpp")):
                    try:
                        sz = entry.stat(follow_symlinks=False).st_size
                    except Exception:
                        sz = 0
                    tasks.append((entry.path, sz, entry.path.lower()))

        self._ilog("INFO",
                   f"Analyse du SDK Windows — {len(tasks):,} fichiers d'en-tête, veuillez patienter...")
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._scan_sdk_header, p, s, pl): p
                    for p, s, pl in tasks}
            for _ in as_completed(futs):
                pass
        self._flush_logs()

    def _kill_malicious_processes(self):
        self._ilog("INFO", "Recherche des processus Luckyware en cours...")
        for proc in MALICIOUS_PROCESSES:
            self._kill_process(proc)

    def block_network(self):
        if not is_admin():
            self._ilog("WARN", "Droits admin requis pour modifier HOSTS / le pare-feu.")
            return
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                current = f.read()
        except Exception as e:
            self._ilog("WARN", f"Lecture de HOSTS impossible : {e}")
            current = ""

        added = 0
        try:
            with open(hosts_path, "a", encoding="utf-8") as f:
                for d in C2_DOMAINS:
                    if d not in current:
                        f.write(f"\n0.0.0.0 {d}")
                        added += 1
        except Exception as e:
            self._ilog("WARN", f"Erreur d'écriture HOSTS : {e}")

        self._ilog("CLEAN",
                   f"HOSTS : {added} nouveaux domaines C2 bloqués "
                   f"({len(C2_DOMAINS) - added} déjà présents).")

        added_ips = 0
        for ip in C2_IPS:
            rule = f"LUCKYKILLER_BLOCK_{ip.replace('.', '_')}"
            chk = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule}"],
                capture_output=True
            )
            if chk.returncode != 0:
                r = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule}", "dir=out", "action=block", f"remoteip={ip}"
                ], capture_output=True)
                if r.returncode == 0:
                    added_ips += 1

        self._ilog("CLEAN", f"Pare-feu : {added_ips} nouvelles règles de blocage d'IP ajoutées.")
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
        self._ilog("CLEAN", "Cache DNS vidé.")

    def _dispatch(self, entry_tuple):
        path, ext, name, size = entry_tuple
        path_lower = path.lower()
        self._files_scanned += 1

        if name in IMGUI_FILENAMES_SET:
            self._scan_imgui(path, size, path_lower)
            return

        if ext == ".exe" or ext == ".dll":
            self._scan_pe(path, size)
            self._scan_yara(path)
        elif ext == ".vcxproj" or ext == ".csproj":
            self._scan_vcxproj(path, size)
        elif ext == ".suo":
            self._scan_suo(path, size)
        elif ext == ".h" or ext == ".hpp":
            self._scan_sdk_header(path, size, path_lower)
        elif ext == ".cpp":
            self._scan_imgui(path, size, path_lower)
        elif ext in TEXT_INDICATOR_EXTENSIONS:
            self._scan_indicators(path, size)

    def _collect_files_with_spinner(self):
        SPINNERS = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        found   = [0]
        stopped = [False]
        result  = []

        def _walk():
            try:
                for root in self.scan_roots:
                    if not os.path.exists(root):
                        continue
                    try:
                        for entry in _fast_walk(root, SKIP_DIRS):
                            ext = os.path.splitext(entry.name)[1].lower()
                            if ext in TARGET_EXTENSIONS:
                                try:
                                    size = entry.stat(follow_symlinks=False).st_size
                                except OSError:
                                    size = 0
                                result.append((
                                    entry.path,
                                    ext,
                                    entry.name.lower(),
                                    size,
                                ))
                                found[0] += 1
                    except OSError:
                        # racine devenue inaccessible en cours de route : on continue
                        continue
            finally:
                stopped[0] = True

        t = threading.Thread(target=_walk, daemon=True)
        t.start()
        i = 0
        while not stopped[0]:
            sp = SPINNERS[i % len(SPINNERS)]
            print(
                f"\r  {CYAN}{sp}{RESET}  Veuillez patienter — collecte des fichiers à analyser...  "
                f"{CYAN}{found[0]:,}{RESET} fichiers trouvés",
                end="", flush=True
            )
            i += 1
            time.sleep(0.08)
        t.join()

        print(
            f"\r  {GREEN}✓{RESET}  Collecte terminée — "
            f"{CYAN}{len(result):,}{RESET} fichiers pertinents trouvés.               "
        )
        return result

    def run(self):
        self._start_time = time.time()

        self._kill_malicious_processes()
        if self.block:
            self.block_network()

        print()
        all_files = self._collect_files_with_spinner()
        total     = len(all_files)

        if total == 0:
            self._ilog("WARN", "Aucun fichier pertinent trouvé dans le(s) chemin(s) indiqué(s).")
            self._scan_browser_staging()
            self._scan_browser_extensions()
            self._scan_browser_shortcuts()
            self._scan_registry_persistence()
            self._print_report()
            return

        sample_rate = 600
        est_str     = fmt_eta(total / sample_rate)
        print(
            f"\n  {DIM}Durée estimée du scan : ~{est_str}  "
            f"({self.workers} threads, {total:,} fichiers){RESET}\n"
        )

        done      = 0
        _lock     = threading.Lock()
        BAR_W     = 38

        from collections import deque
        _rate_window = deque()
        _WINDOW_SECS = 15.0
        _prev_lines  = [0]   # lines drawn in last redraw, for cursor rewind

        def _smooth_rate():
            now = time.time()
            _rate_window.append((now, done))
            while len(_rate_window) > 1 and now - _rate_window[0][0] > _WINDOW_SECS:
                _rate_window.popleft()
            if len(_rate_window) < 2:
                elapsed = now - self._start_time
                return max(done / elapsed, 1) if elapsed > 0 else 1
            dt    = _rate_window[-1][0] - _rate_window[0][0]
            delta = _rate_window[-1][1] - _rate_window[0][1]
            return max(delta / dt, 1) if dt > 0 else 1

        def _trunc_path(path, maxlen=90):
            if len(path) <= maxlen:
                return path
            parts = path.split(os.sep)
            if len(parts) > 4:
                head = os.sep.join(parts[:2])
                tail = os.sep.join(parts[-2:])
                c = f"{head}{os.sep}\u2026{os.sep}{tail}"
                if len(c) <= maxlen:
                    return c
            return "\u2026" + path[-(maxlen - 1):]

        def _redraw():
            rate   = _smooth_rate()
            pct    = done / total
            bar_d  = int(pct * BAR_W)
            bar    = f"{GREEN}{chr(9608) * bar_d}{RESET}{chr(9617) * (BAR_W - bar_d)}"
            remain = (total - done) / rate
            t_col  = RED + BOLD if self.threats else GREEN + BOLD

            lines = []
            lines.append(
                f"  [{bar}]  {CYAN}{pct * 100:5.1f}%{RESET}  "
                f"{done:>7,}/{total:,}  "
                f"{rate:>5.0f} f/s  "
                f"Reste {YELLOW}{fmt_eta(remain)}{RESET}  "
                f"menaces : {t_col}{len(self.threats)}{RESET}"
            )
            lines.append("")
            if self.threats:
                lines.append(f"  {BOLD}Fichiers infectés :{RESET}")
                for t in self.threats:
                    lines.append(f"    {RED}\u2022{RESET}  {_trunc_path(t.path)}")
            else:
                lines.append(f"  {DIM}Fichiers infectés : aucun{RESET}")

            # Rewind cursor to overwrite previous draw
            if _prev_lines[0]:
                sys.stdout.write(f"\033[{_prev_lines[0]}A")

            out = ""
            for ln in lines:
                out += ln + "\033[K\n"   # \033[K clears to end of line
            sys.stdout.write(out)
            sys.stdout.flush()
            _prev_lines[0] = len(lines)

        _redraw()

        def _scan_tick(entry_tuple):
            nonlocal done
            self._dispatch(entry_tuple)
            with _lock:
                done += 1
                if done % 200 == 0 or done == total:
                    _redraw()
                    _autoscroll_to_bottom()

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(_scan_tick, e): e for e in all_files}
            for _ in as_completed(futures):
                pass

        _redraw()
        print()

        self._ilog("INFO", "Analyse de Temp / AppData : recherche des droppers et copies de sessions...")
        self._scan_temp_dirs()
        self._flush_logs()

        self._scan_windows_sdk()
        self._scan_browser_staging()
        self._scan_browser_extensions()
        self._scan_browser_shortcuts()
        self._scan_registry_persistence()

        self._print_report()

    def _print_report(self):
        elapsed = time.time() - self._start_time
        print()
        print(f"{BOLD}{CYAN}{'─'*62}{RESET}")
        print(
            f"  {BOLD}SCAN TERMINÉ{RESET}  ({elapsed:.1f}s)  |  "
            f"Fichiers analysés : {CYAN}{self._files_scanned:,}{RESET}  |  "
            f"Menaces : {(RED + BOLD) if self.threats else (GREEN + BOLD)}"
            f"{len(self.threats)}{RESET}"
        )
        print(f"{BOLD}{CYAN}{'─'*62}{RESET}")
        print()

        if not self.threats:
            print(f"  {GREEN}{BOLD}✓  Aucune infection Luckyware détectée.{RESET}")
        else:
            print(f"  {RED}{BOLD}✗  {len(self.threats)} MENACE(S) DÉTECTÉE(S) :{RESET}")
            print()
            groups = defaultdict(list)
            for t in self.threats:
                groups[t.reason.split(":")[0]].append(t)

            for category, items in sorted(groups.items()):
                print(f"  {YELLOW}{BOLD}[{category}]{RESET}  —  {len(items)} fichier(s)")
                for t in items:
                    acted = any(k in t.action_taken
                                for k in ("nettoy", "effac", "patch", "supprim",
                                          "quarantaine", "déplacée", "désactivée"))
                    col = GREEN if acted else YELLOW
                    print(f"    {RED}•{RESET} {t.path}")
                    print(f"      {col}└─ {t.action_taken}{RESET}")
                print()

            print(f"  {YELLOW}Astuce : lance Bitdefender après le nettoyage pour une vérification finale.{RESET}")
            print(f"  {YELLOW}Un système fortement infecté peut nécessiter une réinstallation propre de Windows.{RESET}")
        print()
        self._print_token_cookie_advice()

    @staticmethod
    def _print_token_cookie_advice():
        print(f"  {BOLD}{CYAN}─ Protection des tokens / cookies / sessions ──{RESET}")
        print(f"  {YELLOW}•{RESET} Déconnecte-toi puis reconnecte-toi partout (invalide les sessions volées).")
        print(f"  {YELLOW}•{RESET} Révoque les tokens API / PAT (GitHub, Discord, Google, clouds…).")
        print(f"  {YELLOW}•{RESET} Vérifie les extensions du navigateur et les autorisations OAuth.")
        print(f"  {YELLOW}•{RESET} Change les mots de passe depuis un appareil sain, jamais depuis la machine infectée.")
        print()


def _fast_walk(top, skip_dirs):
    # Un dossier peut disparaitre pendant le scan (dossiers temporaires, Steam CEF,
    # caches navigateur, etc.) : on ignore silencieusement toute erreur d'accès.
    try:
        with os.scandir(top) as it:
            entries = list(it)
    except OSError:
        # FileNotFoundError, PermissionError, NotADirectoryError, WinError 3/5...
        return

    for entry in entries:
        try:
            is_file = entry.is_file(follow_symlinks=False)
            is_dir  = (not is_file) and entry.is_dir(follow_symlinks=False)
        except OSError:
            continue

        if is_file:
            yield entry
        elif is_dir:
            if entry.name.lower() not in skip_dirs:
                try:
                    yield from _fast_walk(entry.path, skip_dirs)
                except OSError:
                    continue


def get_all_drives():
    drives = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        d = f"{letter}:\\"
        if os.path.exists(d):
            drives.append(d)
    return drives or [os.path.expanduser("~")]


_CHINESE_FRAMES = [
    "Purge des logiciels malveillants  //  Détection de code",
    "Analyse antivirus en cours  //  Protection active",
    "Blocage des menaces réseau  //  Luckyware Terminator",
    "Processus malveillants tués  //  Registre nettoyé",
    "Vérification de l'intégrité  //  Gardien numérique",
    "Moteur de détection  //  LuckyKiller activé",
    "Protection contre l'injection  //  Analyse en temps réel",
    "Scan mémoire actif  //  Barrière de sécurité prête",
    "Éradication des malwares  //  Système purifié",
    "Renseignement sur les menaces  //  Protection zéro-day",
]

_GLITCH_CHARS = "ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ危险恶病扫检清护毒码网"

_title_stop  = threading.Event()
_title_frame = [0]


def _set_transparency(alpha: int = 218):
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if not hwnd:
            return
        GWL_EXSTYLE   = -20
        WS_EX_LAYERED = 0x00080000
        LWA_ALPHA      = 0x00000002
        style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED)
        ctypes.windll.user32.SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA)
        ctypes.windll.user32.MoveWindow(hwnd, 0, 0, 843, 837, True)
    except Exception:
        pass


def _lock_scroll():
    """Remove scrollback buffer and disable QuickEdit so user cannot scroll."""
    try:
        import ctypes.wintypes as wt
        k32 = ctypes.windll.kernel32

        # ── 1. Disable QuickEdit + Insert mode so mouse can't grab the scroll ──
        STD_INPUT  = -10
        STD_OUTPUT = -11
        hin  = k32.GetStdHandle(STD_INPUT)
        hout = k32.GetStdHandle(STD_OUTPUT)

        ENABLE_EXTENDED_FLAGS = 0x0080
        ENABLE_QUICK_EDIT     = 0x0040
        ENABLE_INSERT_MODE    = 0x0020
        mode = wt.DWORD(0)
        k32.GetConsoleMode(hin, ctypes.byref(mode))
        new_mode = (mode.value | ENABLE_EXTENDED_FLAGS) & ~(ENABLE_QUICK_EDIT | ENABLE_INSERT_MODE)
        k32.SetConsoleMode(hin, new_mode)

        # ── 2. Collapse the screen buffer to the window height → no scrollback ──
        class COORD(ctypes.Structure):
            _fields_ = [("X", wt.SHORT), ("Y", wt.SHORT)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", wt.SHORT), ("Top", wt.SHORT),
                        ("Right", wt.SHORT), ("Bottom", wt.SHORT)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [("dwSize",              COORD),
                        ("dwCursorPosition",     COORD),
                        ("wAttributes",          wt.WORD),
                        ("srWindow",             SMALL_RECT),
                        ("dwMaximumWindowSize",  COORD)]

        info = CONSOLE_SCREEN_BUFFER_INFO()
        k32.GetConsoleScreenBufferInfo(hout, ctypes.byref(info))
        win_h = info.srWindow.Bottom - info.srWindow.Top + 1
        win_w = info.srWindow.Right  - info.srWindow.Left + 1

        # Set buffer to exactly the window size → no hidden rows to scroll to
        new_size = COORD(win_w, win_h)
        k32.SetConsoleScreenBufferSize(hout, new_size)

        # Re-anchor the window view to row 0
        win_rect = SMALL_RECT(0, 0, win_w - 1, win_h - 1)
        k32.SetConsoleWindowInfo(hout, True, ctypes.byref(win_rect))
    except Exception:
        pass


def _autoscroll_to_bottom():
    """Force the console view to stay pinned at the cursor row."""
    try:
        import ctypes.wintypes as wt
        k32 = ctypes.windll.kernel32

        class COORD(ctypes.Structure):
            _fields_ = [("X", wt.SHORT), ("Y", wt.SHORT)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", wt.SHORT), ("Top", wt.SHORT),
                        ("Right", wt.SHORT), ("Bottom", wt.SHORT)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [("dwSize",             COORD),
                        ("dwCursorPosition",    COORD),
                        ("wAttributes",         wt.WORD),
                        ("srWindow",            SMALL_RECT),
                        ("dwMaximumWindowSize", COORD)]

        STD_OUTPUT = -11
        hout = k32.GetStdHandle(STD_OUTPUT)
        info = CONSOLE_SCREEN_BUFFER_INFO()
        k32.GetConsoleScreenBufferInfo(hout, ctypes.byref(info))

        win_h    = info.srWindow.Bottom - info.srWindow.Top + 1
        cur_row  = info.dwCursorPosition.Y
        buf_h    = info.dwSize.Y
        win_w    = info.srWindow.Right - info.srWindow.Left + 1

        # Pin view so cursor is always at the bottom row
        top  = max(0, cur_row - win_h + 2)
        bot  = top + win_h - 1
        if bot >= buf_h:
            bot = buf_h - 1
            top = max(0, bot - win_h + 1)

        win_rect = SMALL_RECT(0, top, win_w - 1, bot)
        k32.SetConsoleWindowInfo(hout, True, ctypes.byref(win_rect))
    except Exception:
        pass


def _title_animator():
    import random
    phrases = _CHINESE_FRAMES
    idx     = 0
    while not _title_stop.is_set():
        phrase = phrases[idx % len(phrases)]
        ctypes.windll.kernel32.SetConsoleTitleW(f" LuckyKiller  │  {phrase}")
        _title_frame[0] = idx
        idx += 1
        time.sleep(1.8)


def _start_effects():
    _set_transparency(218)
    _lock_scroll()
    _title_stop.clear()
    t = threading.Thread(target=_title_animator, daemon=True)
    t.start()


def _glitch_line():
    import random
    width  = 70
    frame  = _title_frame[0]
    random.seed(frame)
    chars  = [random.choice(_GLITCH_CHARS) if random.random() < 0.35 else " "
              for _ in range(width)]
    phrase = _CHINESE_FRAMES[frame % len(_CHINESE_FRAMES)]
    centre = phrase.center(width)
    merged = "".join(
        c if centre[i] != " " else chars[i]
        for i, c in enumerate(centre)
    )
    return merged


def print_banner():
    clear()
    print(f"""
{RED}{BOLD}
  ██╗     ██╗   ██╗ ██████╗██╗  ██╗██╗   ██╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗
  ██║     ██║   ██║██╔════╝██║ ██╔╝╚██╗ ██╔╝██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
  ██║     ██║   ██║██║     █████╔╝  ╚████╔╝ █████╔╝ ██║██║     ██║     █████╗  ██████╔╝
  ██║     ██║   ██║██║     ██╔═██╗   ╚██╔╝  ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
  ███████╗╚██████╔╝╚██████╗██║  ██╗   ██║   ██║  ██╗██║███████╗███████╗███████╗██║  ██║
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}""")
    print()
    print(f"  {DIM}RAT Luckyware / Lumma — détection, suppression, blocage et protection des sessions{RESET}")
    status = (f"{GREEN}Administrateur{RESET}" if is_admin()
              else f"{YELLOW}Utilisateur (limité — certaines fonctions exigent l'admin){RESET}")
    print(f"  Exécuté en tant que : {status}")
    print(f"  {DIM}{'─'*70}{RESET}")
    print()


def prompt_path():
    print(f"  {CYAN}Entre un dossier à analyser, ou appuie sur Entrée pour analyser tous les disques :{RESET}")
    val = input(f"  {BOLD}>{RESET} ").strip().strip('"')
    if not val:
        return None
    if not os.path.exists(val):
        print(f"\n  {YELLOW}Chemin introuvable. Analyse de tous les disques par défaut.{RESET}")
        return None
    return val


def menu():
    _start_effects()
    while True:
        print_banner()
        print(f"  {BOLD}MENU PRINCIPAL{RESET}\n")
        options = [
            ("1", "Scan complet + suppression auto + blocage C2",
             "Recommandé — analyse tout, supprime les menaces, bloque le réseau"),
            ("2", "Scan complet seulement (sans suppression)",
             "Détecte les menaces et affiche le rapport sans rien modifier"),
            ("3", "Bloquer seulement les domaines et IP C2",
             "Met à jour le fichier HOSTS et ajoute les règles de pare-feu"),
            ("4", "Tuer seulement les processus Luckyware / Lumma",
             "Termine Berok.exe, Retev.exe, Zetolac.exe, HPSR.exe, Lumma*.exe, Stealer.exe"),
            ("5", "Analyser un dossier précis",
             "Choisir un dossier personnalisé à analyser"),
            ("6", "Protéger les tokens / cookies (infostealer)",
             "Extensions, copies de sessions, raccourcis et persistance Lumma"),
            ("0", "Quitter", ""),
        ]
        for num, label, desc in options:
            col = RED if num == "1" else CYAN
            print(f"  {col}{BOLD}[{num}]{RESET}  {BOLD}{label}{RESET}")
            if desc:
                print(f"       {DIM}{desc}{RESET}")
            print()

        choice = input(f"  {BOLD}Choisis une option : {RESET}").strip()
        print()

        if choice == "0":
            print(f"  {GREEN}Au revoir.{RESET}\n")
            break

        elif choice == "1":
            LuckyKiller(scan_roots=get_all_drives(),
                        auto_remove=True, block=True).run()
            pause()

        elif choice == "2":
            LuckyKiller(scan_roots=get_all_drives(),
                        auto_remove=False, block=False).run()
            pause()

        elif choice == "3":
            if not is_admin():
                print(f"  {RED}Droits administrateur requis.{RESET}")
            else:
                tmp = LuckyKiller(scan_roots=[], block=True)
                tmp.block_network()
                print(f"\n  {GREEN}Terminé.{RESET}")
            pause()

        elif choice == "4":
            tmp = LuckyKiller(scan_roots=[])
            tmp._kill_malicious_processes()
            print(f"\n  {GREEN}Nettoyage des processus terminé.{RESET}")
            pause()

        elif choice == "5":
            path = prompt_path()
            roots = [path] if path else get_all_drives()
            print()
            print(f"  {CYAN}Supprimer les menaces automatiquement ?{RESET}")
            print(f"  {BOLD}[1]{RESET} Oui — analyser et supprimer")
            print(f"  {BOLD}[2]{RESET} Non — analyser et signaler seulement")
            print()
            sub = input(f"  {BOLD}>{RESET} ").strip()
            LuckyKiller(scan_roots=roots, auto_remove=(sub == "1"),
                        block=True).run()
            pause()

        elif choice == "6":
            tmp = LuckyKiller(scan_roots=[], auto_remove=True, block=False)
            tmp._start_time = time.time()
            tmp._kill_malicious_processes()
            tmp._scan_browser_staging()
            tmp._scan_browser_extensions()
            tmp._scan_browser_shortcuts()
            tmp._scan_registry_persistence()
            tmp._flush_logs()
            tmp._print_report()
            pause()

        else:
            print(f"  {YELLOW}Option invalide. Réessaie.{RESET}")
            time.sleep(1)


if __name__ == "__main__":
    menu()