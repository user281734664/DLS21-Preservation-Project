#!/usr/bin/env python3
"""
DLS21 Preservation Project
Reproducible DLS21 v8.13 LAB / USER-CA APK builder.

This tool DOES NOT download or redistribute Dream League Soccer 2021.
The researcher must provide their own compatible DLS21 v8.13 APK.

Target:
  package:     com.firsttouchgames.dls7
  versionName: 8.13
  versionCode: 38

Deliberate LAB changes:
  1) android:debuggable="true"
  2) android:networkSecurityConfig="@xml/network_security_config"
  3) android:usesCleartextTraffic="true"
  4) user-installed CAs are trusted for api.ftpub.net
  5) APK is rebuilt, zipaligned and signed with a LOCAL LAB key

The script intentionally does NOT patch libDLS21.so, game assets,
database files, or application smali logic.

No third-party Python packages are required.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

PACKAGE = "com.firsttouchgames.dls7"
VERSION_NAME = "8.13"
VERSION_CODE = "38"

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = "{" + ANDROID_NS + "}"

DEFAULT_OUTPUT = "DLS21_813_USERCA_LAB_signed.apk"
DEFAULT_KEYSTORE = ".dls21-lab.keystore"
DEFAULT_ALIAS = "dls21lab"
DEFAULT_STORE_PASS = "dls21lab-local"

NETWORK_SECURITY_XML = '''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="false">api.ftpub.net</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
</network-security-config>
'''


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pretty_cmd(cmd: list[str]) -> str:
    return " ".join(f'"{x}"' if (" " in x or "\t" in x) else x for x in cmd)


def run(cmd: list[str]) -> None:
    cmd = [str(x) for x in cmd]
    print("\n+", pretty_cmd(cmd))
    if os.name == "nt" and cmd[0].lower().endswith((".bat", ".cmd")):
        subprocess.run(subprocess.list2cmdline(cmd), shell=True, check=True)
    else:
        subprocess.run(cmd, check=True)


def version_key(text: str) -> tuple:
    parts = re.split(r"([0-9]+)", text)
    return tuple((1, int(p)) if p.isdigit() else (0, p.lower()) for p in parts)


def locate_apktool(explicit: str | None = None) -> str | None:
    if explicit:
        p = Path(explicit).expanduser()
        if p.exists():
            return str(p.resolve())
        return shutil.which(explicit)

    for name in ("apktool", "apktool.bat", "apktool.cmd"):
        found = shutil.which(name)
        if found:
            return found

    candidates = [
        Path.cwd() / "apktool.bat",
        Path.cwd() / "tools" / "apktool.bat",
        Path.home() / "Downloads" / "apktool" / "apktool.bat",
    ]
    for p in candidates:
        if p.exists():
            return str(p.resolve())
    return None


def android_sdk_roots() -> list[Path]:
    roots: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))

    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            roots.append(Path(local) / "Android" / "Sdk")
    else:
        roots.extend([
            Path.home() / "Android" / "Sdk",
            Path.home() / "Library" / "Android" / "sdk",
        ])
    return roots


def locate_android_tool(name: str, explicit: str | None = None) -> str | None:
    if explicit:
        p = Path(explicit).expanduser()
        if p.exists():
            return str(p.resolve())
        return shutil.which(explicit)

    for candidate in (name, name + ".exe", name + ".bat", name + ".cmd"):
        found = shutil.which(candidate)
        if found:
            return found

    found_tools: list[Path] = []
    for sdk in android_sdk_roots():
        build_tools = sdk / "build-tools"
        if not build_tools.is_dir():
            continue
        for version in build_tools.iterdir():
            for filename in (name, name + ".exe", name + ".bat", name + ".cmd"):
                p = version / filename
                if p.exists():
                    found_tools.append(p)

    found_tools.sort(key=lambda x: version_key(x.parent.name), reverse=True)
    return str(found_tools[0].resolve()) if found_tools else None


def locate_keytool(explicit: str | None = None) -> str | None:
    if explicit:
        p = Path(explicit).expanduser()
        if p.exists():
            return str(p.resolve())
        return shutil.which(explicit)

    found = shutil.which("keytool") or shutil.which("keytool.exe")
    if found:
        return found

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        for filename in ("keytool.exe", "keytool"):
            p = Path(java_home) / "bin" / filename
            if p.exists():
                return str(p.resolve())

    if os.name == "nt":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        roots = [program_files / "Eclipse Adoptium", program_files / "Java"]
        results: list[Path] = []
        for root in roots:
            if root.exists():
                results.extend(root.glob("jdk*/bin/keytool.exe"))
        if results:
            results.sort(key=lambda x: version_key(x.parts[-3]), reverse=True)
            return str(results[0].resolve())

    return None


def payload_hashes(apk: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    with zipfile.ZipFile(apk, "r") as z:
        for name in z.namelist():
            filename = Path(name).name
            is_dex = bool(re.fullmatch(r"classes(?:\d+)?\.dex", filename))
            is_engine = name.startswith("lib/") and name.endswith("/libDLS21.so")
            if is_dex or is_engine:
                result[name] = sha256_bytes(z.read(name))
    return result


def parse_apktool_yml(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, None

    text = path.read_text(encoding="utf-8", errors="replace")
    version_code = None
    version_name = None

    match = re.search(r'''(?m)^\s*versionCode:\s*['"]?([^'"\r\n]+)''', text)
    if match:
        version_code = match.group(1).strip()

    match = re.search(r'''(?m)^\s*versionName:\s*['"]?([^'"\r\n]+)''', text)
    if match:
        version_name = match.group(1).strip()

    return version_code, version_name


def verify_target(decoded: Path) -> None:
    manifest = decoded / "AndroidManifest.xml"
    tree = ET.parse(manifest)
    root = tree.getroot()

    package = root.attrib.get("package", "")
    version_name = root.attrib.get(A + "versionName")
    version_code = root.attrib.get(A + "versionCode")

    yaml_code, yaml_name = parse_apktool_yml(decoded / "apktool.yml")
    version_code = version_code or yaml_code
    version_name = version_name or yaml_name

    if package != PACKAGE:
        raise RuntimeError(f"Wrong package: {package or '<missing>'}")
    if version_name and version_name != VERSION_NAME:
        raise RuntimeError(f"Wrong DLS version. Expected {VERSION_NAME}, found {version_name}.")
    if version_code and str(version_code) != VERSION_CODE:
        raise RuntimeError(f"Wrong versionCode. Expected {VERSION_CODE}, found {version_code}.")

    print(f"\n[OK] Target: {package} versionName={version_name or '?'} versionCode={version_code or '?'}")


def patch_manifest(decoded: Path) -> None:
    manifest = decoded / "AndroidManifest.xml"
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(manifest)
    root = tree.getroot()

    application = root.find("application")
    if application is None:
        raise RuntimeError("<application> not found in AndroidManifest.xml")

    application.set(A + "debuggable", "true")
    application.set(A + "networkSecurityConfig", "@xml/network_security_config")
    application.set(A + "usesCleartextTraffic", "true")
    tree.write(manifest, encoding="utf-8", xml_declaration=True)


def patch_network_security(decoded: Path) -> None:
    directory = decoded / "res" / "xml"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "network_security_config.xml").write_text(
        NETWORK_SECURITY_XML, encoding="utf-8", newline="\n"
    )


def create_keystore(keytool: str, keystore: Path, alias: str, password: str) -> None:
    if keystore.exists():
        print(f"[OK] Reusing signing key: {keystore}")
        return

    keystore.parent.mkdir(parents=True, exist_ok=True)
    print("\n[INFO] Creating local LAB signing key...")
    run([
        keytool,
        "-genkeypair",
        "-v",
        "-keystore", str(keystore),
        "-storetype", "PKCS12",
        "-storepass", password,
        "-keypass", password,
        "-alias", alias,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=DLS21 Preservation LAB, OU=Research, O=DLS21 Preservation Project, C=BR",
    ])


def verify_payload(original_hashes: dict[str, str], generated: Path) -> bool:
    generated_hashes = payload_hashes(generated)
    success = True

    print("\nChecking DEX/native payload:")
    if not original_hashes:
        print("[WARNING] No classes*.dex or libDLS21.so entries were found in the input.")
        return False

    for name, digest in sorted(original_hashes.items()):
        new_digest = generated_hashes.get(name)
        if new_digest is None:
            print(f"[WARNING] missing: {name}")
            success = False
        elif new_digest != digest:
            print(f"[WARNING] changed: {name}")
            print(f"          before: {digest}")
            print(f"          after : {new_digest}")
            success = False
        else:
            print(f"[OK] unchanged: {name}")

    return success


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a DLS21 v8.13 LAB / USER-CA APK.")
    parser.add_argument("apk", type=Path, help="Researcher's own DLS21 v8.13 APK")
    parser.add_argument("-o", "--output", type=Path, default=Path(DEFAULT_OUTPUT))
    parser.add_argument("--apktool")
    parser.add_argument("--zipalign")
    parser.add_argument("--apksigner")
    parser.add_argument("--keytool")
    parser.add_argument("--keystore", type=Path, default=Path(DEFAULT_KEYSTORE))
    parser.add_argument("--alias", default=DEFAULT_ALIAS)
    parser.add_argument(
        "--ks-pass",
        default=os.environ.get("DLS21_LAB_KS_PASS", DEFAULT_STORE_PASS),
        help="LAB keystore password. Prefer DLS21_LAB_KS_PASS for a persistent key.",
    )
    parser.add_argument("--no-sign", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args()

    original = args.apk.expanduser().resolve()
    output = args.output.expanduser().resolve()
    keystore = args.keystore.expanduser().resolve()

    if not original.is_file():
        eprint(f"[ERROR] APK not found: {original}")
        return 2

    try:
        with zipfile.ZipFile(original, "r") as z:
            if "AndroidManifest.xml" not in z.namelist():
                eprint("[ERROR] Input is not a normal Android APK ZIP.")
                return 2
    except zipfile.BadZipFile:
        eprint("[ERROR] Invalid APK/ZIP.")
        return 2

    apktool = locate_apktool(args.apktool)
    zipalign = locate_android_tool("zipalign", args.zipalign)

    if not apktool:
        eprint("[ERROR] apktool not found. Install Apktool or pass --apktool PATH.")
        return 2
    if not zipalign:
        eprint("[ERROR] zipalign not found. Install Android SDK Build-Tools or pass --zipalign PATH.")
        return 2

    apksigner = None
    keytool = None
    if not args.no_sign:
        apksigner = locate_android_tool("apksigner", args.apksigner)
        keytool = locate_keytool(args.keytool)
        if not apksigner:
            eprint("[ERROR] apksigner not found. Install Android SDK Build-Tools or pass --apksigner PATH.")
            return 2
        if not keytool:
            eprint("[ERROR] keytool not found. Install a JDK or pass --keytool PATH.")
            return 2

    print("=" * 72)
    print("DLS21 Preservation Project - v8.13 LAB / USER-CA Builder")
    print("=" * 72)
    print(f"[INPUT]      {original}")
    print(f"[SHA256]     {sha256_file(original)}")
    print(f"[APKTOOL]    {apktool}")
    print(f"[ZIPALIGN]   {zipalign}")
    if apksigner:
        print(f"[APKSIGNER]  {apksigner}")
    if keytool:
        print(f"[KEYTOOL]    {keytool}")

    original_payload = payload_hashes(original)
    output.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dls21_lab_build_", dir=str(output.parent)))
    decoded = work / "decoded"
    unsigned = work / "DLS21_813_USERCA_unsigned.apk"
    aligned = work / "DLS21_813_USERCA_aligned.apk"

    try:
        run([apktool, "d", "-f", "-s", str(original), "-o", str(decoded)])
        verify_target(decoded)
        patch_manifest(decoded)
        patch_network_security(decoded)

        print('\n[OK] android:debuggable="true"')
        print("[OK] USER CA enabled for api.ftpub.net")
        print("[OK] networkSecurityConfig set to @xml/network_security_config")

        run([apktool, "b", str(decoded), "-o", str(unsigned)])
        run([zipalign, "-f", "-p", "4", str(unsigned), str(aligned)])

        if args.no_sign:
            shutil.copy2(aligned, output)
        else:
            assert apksigner is not None and keytool is not None
            create_keystore(keytool, keystore, args.alias, args.ks_pass)
            run([
                apksigner, "sign",
                "--ks", str(keystore),
                "--ks-key-alias", args.alias,
                "--ks-pass", "pass:" + args.ks_pass,
                "--key-pass", "pass:" + args.ks_pass,
                "--out", str(output),
                str(aligned),
            ])
            run([apksigner, "verify", "--verbose", "--print-certs", str(output)])

        print(f"\n[OUTPUT] {output}")
        print(f"[SHA256] {sha256_file(output)}")
        payload_ok = verify_payload(original_payload, output)

        print("\n" + "=" * 72)
        if payload_ok:
            print("SUCCESS")
            print("classes*.dex and libDLS21.so remained byte-identical.")
            result = 0
        else:
            print("BUILD COMPLETED WITH WARNINGS")
            print("Review the payload warnings before using this build as the reference LAB APK.")
            result = 1
        print("=" * 72)

        print("\nNext:")
        print("1. Install the mitmproxy CA as an Android USER certificate.")
        print("2. Configure the Android Wi-Fi proxy to the PC running mitmproxy.")
        print("3. Run: mitmdump -s mock/dls_mock.py --listen-port 8080")
        print("4. Install/start the generated LAB APK.")
        return result

    except subprocess.CalledProcessError as exc:
        eprint(f"\n[ERROR] External tool failed with exit code {exc.returncode}.")
        return exc.returncode or 1
    except Exception as exc:
        eprint(f"\n[ERROR] {exc}")
        return 1
    finally:
        if args.keep_work:
            print(f"\n[INFO] Work directory kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
