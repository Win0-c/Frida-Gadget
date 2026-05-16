"""
Frida Gadget Injector for Android APK

This script allows you to inject the Frida gadget library into an Android APK.
It provides various functionalities including:
- Decompiling the APK using apktool
- Downloading the appropriate Frida gadget library based on the device architecture
- Injecting the Frida gadget library into the APK
- Modifying the AndroidManifest.xml to add necessary permissions
- Recompiling the APK
- Optionally signing the APK using uber-apk-signer
"""

import os
import re
import sys
import shutil
import subprocess
import json
import tempfile
import zipfile
from shutil import which
from pathlib import Path
import click
from androguard.core.apk import APK
from .apk_utils import get_main_activity
from .logger import logger
from .__version__ import __version__
from .frida_github import FridaGithub
from .uber_apk_signer_github import UberApkSignerGithub
from . import INSTALLED_FRIDA_VERSION


p = Path(__file__)
ROOT_DIR = p.parent.resolve()
TEMP_DIR = ROOT_DIR.joinpath("temp")
FILE_DIR = ROOT_DIR.joinpath("files")

APKTOOL = which("apktool")
ARCH_DIRNAMES = {
    "arm": "armeabi-v7a",
    "x86": "x86",
    "arm64": "arm64-v8a",
    "x86_64": "x86_64",
}
SUPPORTED_ARCHS = list(ARCH_DIRNAMES.keys())
PRESETS = ["listen", "script", "dump", "quiet", "debug"]


def inspect_apk(apk_path: str):
    """Inspect an APK and return patcher-friendly defaults."""
    apk_file = Path(apk_path)
    result = {
        "apk": str(apk_file.resolve()),
        "name": apk_file.stem,
        "package": None,
        "main_activity": None,
        "activities": [],
        "architectures": [],
        "recommended_arch": "arm64",
        "recommended_preset": "listen",
        "has_gadget": False,
        "is_split_or_config_apk": False,
        "output_dir": str(apk_file.parent.joinpath("output")),
        "dump_output": str(apk_file.parent.joinpath("dumps", apk_file.stem)),
        "warnings": [],
    }

    if not apk_file.exists():
        result["warnings"].append("APK path does not exist.")
        return result

    try:
        apk = APK(str(apk_file))
        result["package"] = apk.get_package()
        activities = apk.get_activities() or []
        result["activities"] = list(activities)
        main_activity = get_main_activity(apk)
        if main_activity != -1:
            result["main_activity"] = main_activity
        elif len(activities) == 1:
            result["main_activity"] = activities[0]
        else:
            result["warnings"].append("Multiple or missing launch activities. Pick Main Activity manually if patching fails.")
    except Exception as exc:
        result["warnings"].append(f"Manifest inspection failed: {exc}")

    arch_mapping = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86": "x86",
        "x86_64": "x86_64",
    }
    try:
        with zipfile.ZipFile(apk_file, "r") as archive:
            names = archive.namelist()
            abis = sorted({
                parts[1]
                for name in names
                if name.startswith("lib/") and name.endswith(".so")
                for parts in [name.split("/")]
                if len(parts) >= 3 and parts[1] in arch_mapping
            })
            result["architectures"] = [arch_mapping[abi] for abi in abis]
            result["has_gadget"] = any("frida-gadget" in Path(name).name for name in names)
            result["is_split_or_config_apk"] = any(name.startswith("split_config.") for name in names)
    except Exception as exc:
        result["warnings"].append(f"APK zip inspection failed: {exc}")

    if len(result["architectures"]) > 1:
        result["recommended_arch"] = "multi-arch"
    elif result["architectures"]:
        result["recommended_arch"] = result["architectures"][0]
    if result["has_gadget"]:
        result["warnings"].append("APK appears to already contain Frida Gadget.")
    if result["is_split_or_config_apk"]:
        result["warnings"].append("APK looks like a split/config APK. A full base APK is usually needed.")

    return result


def run_apktool(option: list, apk_path: str):
    """Run apktool with option

    Args:
        option (list|str): option of apktool
        apk_path (str): path of apk file

    """

    pipe = subprocess.PIPE
    cmd = APKTOOL.split() + option + [apk_path]
    with subprocess.Popen(
        cmd, stdin=pipe, stdout=sys.stdout, stderr=sys.stderr
    ) as process:
        process.communicate(b"\n")
        if process.returncode != 0:
            recommend_options = ["--no-res", "--use-aapt2"]
            for opt in recommend_options:
                if opt in option:
                    recommend_options.remove(opt)

            logger.error(
                "It looks like you're having trouble with apktool.\n"
                "Consider trying the '%s' options, or if you'd prefer more control,\n"
                "you can manually specify apktool settings using ['--decompile-opts', '--recompile-opts', '--apktool-path'].",
                recommend_options,
            )

            raise subprocess.CalledProcessError(
                process.returncode, cmd, sys.stdout, sys.stderr
            )
        return True


def download_gadget(arch: str, frida_version: str = None):
    """Download the frida gadget library

    Args:
        arch (str): architecture of the device
        frida_version (str): specific frida version to use
    """
    if frida_version:
        logger.info("Using specified frida version: %s", frida_version)
        version = frida_version
    else:
        logger.info("Auto-detected your frida version: %s", INSTALLED_FRIDA_VERSION)
        version = INSTALLED_FRIDA_VERSION

    frida_github = FridaGithub(version)
    assets = frida_github.get_assets()
    file = f"frida-gadget-{version}-android-{arch}.so.xz"
    for asset in assets:
        if asset["name"] == file:
            logger.debug(
                "Downloading the frida gadget library(%s) for %s", version, arch
            )
            so_gadget_path = str(FILE_DIR.joinpath(file[:-3]))
            return frida_github.download_gadget_so(
                asset["browser_download_url"], so_gadget_path
            )

    raise FileNotFoundError(f"'{file}' not found in the github releases")


def resolve_local_gadget(local_gadget: str, arch: str) -> str:
    """Resolve a custom local Gadget .so path for an architecture."""
    path = Path(local_gadget).expanduser().resolve()
    if path.is_file():
        return str(path)
    if not path.is_dir():
        raise FileNotFoundError(f"Local gadget path not found: {path}")

    candidates = [
        path.joinpath(ARCH_DIRNAMES[arch], "libfrida-gadget.so"),
        path.joinpath(arch, "libfrida-gadget.so"),
        path.joinpath(f"libfrida-gadget-{arch}.so"),
        path.joinpath("libfrida-gadget.so"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError(
        f"No local Gadget .so found for {arch} in {path}. "
        "Expected libfrida-gadget.so, libfrida-gadget-<arch>.so, "
        "or <abi>/libfrida-gadget.so."
    )


def get_gadget_path(arch: str, frida_version: str = None, local_gadget: str = None):
    if local_gadget:
        logger.info("Using local Gadget build for %s: %s", arch, local_gadget)
        return resolve_local_gadget(local_gadget, arch)
    return download_gadget(arch, frida_version)


def make_preset_config(preset: str, script_path: str = None):
    """Return a friendly Gadget config for common workflows."""
    if preset not in PRESETS:
        raise ValueError(f"Unsupported preset: {preset}")

    if preset == "script":
        if not script_path:
            raise ValueError("--preset script requires --js")
        return {
            "interaction": {
                "type": "script",
                "path": script_path,
                "on_change": "reload",
            }
        }

    if preset == "dump":
        return {
            "interaction": {
                "type": "listen",
                "address": "127.0.0.1",
                "port": 27042,
                "on_load": "resume",
            }
        }

    if preset == "quiet":
        return {
            "interaction": {
                "type": "listen",
                "address": "127.0.0.1",
                "port": 27042,
                "on_load": "resume",
            }
        }

    return {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": 27042,
            "on_load": "wait",
        }
    }


def write_json(path: Path, data):
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def run_doctor(apktool_path: str = None):
    """Print a quick environment health report."""
    checks = {
        "python": sys.executable,
        "apktool": apktool_path or which("apktool"),
        "java": which("java"),
        "adb": which("adb"),
        "frida": which("frida"),
        "frida-dexdump": which("frida-dexdump"),
    }

    workspace = ROOT_DIR.parent.parent
    dexdump_venv = workspace.joinpath(".venv-dexdump", "Scripts", "python.exe")
    click.echo("Frida Gadget doctor")
    click.echo("-------------------")
    for name, path in checks.items():
        status = "OK" if path else "MISSING"
        click.echo(f"{name:14} {status:8} {path or ''}")
    click.echo(f"{'dexdump venv':14} {'OK' if dexdump_venv.exists() else 'MISSING':8} {dexdump_venv}")
    click.echo(f"{'gadget source':14} {'OK' if workspace.joinpath('frida-source', 'subprojects', 'frida-core', 'lib', 'gadget', 'gadget.vala').exists() else 'MISSING':8}")


def run_dumper(package: str, output_dir: str = None, deep: bool = False, maps: bool = False):
    """Run the local frida-dexdump environment if available."""
    workspace = ROOT_DIR.parent.parent
    dexdump_python = workspace.joinpath(".venv-dexdump", "Scripts", "python.exe")
    if not dexdump_python.exists():
        raise FileNotFoundError(f"Dumper venv not found: {dexdump_python}")

    cmd = [str(dexdump_python), "-m", "frida_dexdump", "-U", "-f", package]
    if output_dir:
        cmd += ["-o", output_dir]
    if deep:
        cmd.append("-d")
    if maps:
        cmd.append("--maps")
    subprocess.run(cmd, check=True)


def download_signer():
    """Download the Uber Apk Signer"""
    signer_github = UberApkSignerGithub()
    assets = signer_github.get_assets()
    file = f"uber-apk-signer-{signer_github.signer_version}.jar"
    signer_path = str(FILE_DIR.joinpath(file))
    if os.path.exists(signer_path):
        return signer_path

    logger.debug("Downloading the %s file for signing", file)
    return signer_github.download_signer_jar(assets, signer_path)


def insert_loadlibary(decompiled_path, main_activity, load_library_name):
    """Inject loadlibary code to main activity

    Args:
        decompiled_path (str): decomplied path of apk file
        main_activity (str): main activity of apk file
        load_library_name (str): name of load library
    """
    logger.debug("Searching for the main activity in the smali files")
    target_smali = None
    target_smali_class_number = None

    target_relative_path = main_activity.replace(".", os.sep)
    for directory in decompiled_path.iterdir():
        if directory.is_dir() and directory.name.startswith("smali"):
            target_smali = directory.joinpath(target_relative_path + ".smali")
            if target_smali.exists():
                if directory.name.startswith("smali_classes"):
                    target_smali_class_number = int(directory.name.split("smali_classes")[1])
                break

    if not target_smali or not target_smali.exists():
        raise FileNotFoundError(f"The target class file {target_smali} was not found.")

    logger.debug("Found the main activity at '%s'", str(target_smali))
    text = target_smali.read_text()

    text = text.replace("invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exit(I)V", "")
    text = text.split("\n")

    logger.debug("Locating the entrypoint method and injecting the loadLibrary code")
    status = False
    entrypoints = [" onCreate(", "<init>"]
    for entrypoint in entrypoints:
        idx = 0
        while idx != len(text):
            line = text[idx].strip()
            if line.startswith(".method") and entrypoint in line:
                if ".locals" not in text[idx + 1]:
                    idx += 1
                    continue
                else:
                    # Increase the number of locals 0 to 1
                    if ".locals 0" in text[idx + 1]:
                        text[idx + 1] = text[idx + 1].replace(".locals 0", ".locals 1")

                if load_library_name.startswith("lib"):
                    load_library_name = load_library_name[3:]
                text.insert(
                    idx + 2,
                    "    invoke-static {v0}, "
                    "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
                )
                text.insert(idx + 2, f"    const-string v0, " f'"{load_library_name}"')
                status = True
                break
            idx += 1

        if status:
            break

    if not status:
        logger.error("Cannot find the appropriate position in the main activity.")
        logger.error(
            "Please report the issue at %s with the following information:",
            "https://github.com/ksg97031/frida-gadget/issues",
        )
        logger.error("APK Name: <Your APK Name>")
        logger.error("APK Version: <Your APK Version>")
        logger.error("APKTOOL Version: <Your APKTOOL Version>")
        sys.exit(-1)

    # Replace the smali file with the new one
    target_smali.write_text("\n".join(text))
    return target_smali_class_number

def modify_manifest(decompiled_path):
    """Modify manifest permissions

    Args:
        decompiled_path (str): decomplied path of apk file
    """
    # Add internet permission
    logger.debug("Checking internet permission and extractNativeLibs settings")
    android_manifest = decompiled_path.joinpath("AndroidManifest.xml")
    txt = android_manifest.read_text(encoding="utf-8")
    pos = txt.index("</manifest>")
    permission = "android.permission.INTERNET"

    if permission not in txt:
        logger.debug(
            "Adding 'android.permission.INTERNET' permission to AndroidManifest.xml"
        )
        permissions_txt = f"<uses-permission android:name='{permission}'/>"
        txt = txt[:pos] + permissions_txt + txt[pos:]

    # Set extractNativeLibs to true
    if ':extractNativeLibs="false"' in txt:
        logger.debug('Editing the extractNativeLibs="true"')
        txt = txt.replace(':extractNativeLibs="false"', ':extractNativeLibs="true"')
    android_manifest.write_text(txt, encoding="utf-8")


def detect_apk_architectures(decompiled_path):
    """Detect architectures from the APK's lib directory

    Args:
        decompiled_path (str): decompiled path of apk file

    Returns:
        list: List of detected architectures
    """
    lib_dir = decompiled_path.joinpath("lib")
    if not lib_dir.exists():
        logger.warning(
            "No lib directory found in the APK. Returning default architecture (arm64)."
        )
        return ["arm64"]

    arch_mapping = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86": "x86",
        "x86_64": "x86_64",
    }

    detected_archs = []
    for arch_dir in lib_dir.iterdir():
        if arch_dir.is_dir() and arch_dir.name in arch_mapping:
            detected_archs.append(arch_mapping[arch_dir.name])

    if not detected_archs:
        logger.warning(
            "No supported architectures found in the APK. Returning default architecture (arm64)."
        )
        return ["arm64"]

    logger.info("Detected architectures in APK: %s", ", ".join(detected_archs))
    return detected_archs


def inject_gadget_into_apk(
    apk_path: str,
    arch: str,
    decompiled_path: str,
    no_res,
    force_manifest,
    main_activity: str = None,
    config: str = None,
    js: str = None,
    custom_gadget_name: str = None,
    frida_version: str = None,
    local_gadget: str = None,
    preset: str = None,
):
    """Inject frida gadget into an APK

    Args:
        apk (APK): path of apk file
        arch (str): architecture of the device
        decompiled_path (str): decomplied path of apk file

    Raises:
        FileNotFoundError: file not found
        NotImplementedError: not implemented
    """
    apk = APK(apk_path)

    # Handle 'multi-arch' option
    if arch == "multi-arch":
        archs = detect_apk_architectures(decompiled_path)
        logger.info(
            "Using multiple architectures detected from APK: %s", ", ".join(archs)
        )
    else:
        archs = [arch]

    # Get main activity if not provided
    if not main_activity:
        main_activity = get_main_activity(apk)
        if main_activity == -1:  # multiple main activities
            sys.exit(-1)

    if not main_activity:
        if len(apk.get_activities()) == 1:
            logger.warning(
                "The main activity was not found.\n"
                "Using the first activity from the manifest file."
            )
            main_activity = apk.get_activities()[0]
        else:
            logger.error(
                "The main activity was not found.\n"
                "Please specify the main activity using the --main-activity option.\n"
                "Select the activity from %s",
                apk.get_activities(),
            )
            sys.exit(-1)

    # Apply permission to android manifest
    if not no_res or force_manifest:
        modify_manifest(decompiled_path)

    for current_arch in archs:
        gadget_path = get_gadget_path(current_arch, frida_version, local_gadget)
        gadget_name = Path(gadget_path).name

        # Apply custom gadget name if provided
        if custom_gadget_name:
            custom_gadget_name_with_ext = custom_gadget_name + ".so"
            logger.info("Using custom gadget name: %s", custom_gadget_name_with_ext)
            gadget_name = custom_gadget_name_with_ext
        if arch == "multi-arch":
            # TODO: custom gadget name for multi-arch
            gadget_name = "libfrida-gadget.so"
            logger.info("Using multi-arch gadget name: %s", gadget_name)

        # Save the first gadget info for loadLibrary
        # Copy the frida gadget library to the lib directory
        lib = decompiled_path.joinpath("lib")
        if not lib.exists():
            lib.mkdir()

        if current_arch not in ARCH_DIRNAMES:
            raise NotImplementedError(
                f"The architecture '{current_arch}' is not supported."
            )

        arch_dirname = ARCH_DIRNAMES[current_arch]
        lib_arch_dir = lib.joinpath(arch_dirname)
        if not lib_arch_dir.exists():
            lib_arch_dir.mkdir()

        lib_library_name = gadget_name
        if not lib_library_name.startswith("lib"):
            lib_library_name = "lib" + gadget_name
        shutil.copy(gadget_path, lib_arch_dir.joinpath(lib_library_name))

        # Upload gadget config and js files for each architecture
        upload_files = {"config": config, "script": js}
        load_library_name = lib_library_name[:-3]

        if preset and not config and not js:
            config_name = f"{load_library_name}.config.so"
            write_json(lib_arch_dir.joinpath(config_name), make_preset_config(preset))
            logger.debug("Created %s preset config: %s", preset, config_name)
            del upload_files["config"]
        elif js and config:
            with open(config, "r") as f:
                contents = f.read()
                config_data = json.loads(contents)
                if "interaction" not in config_data:
                    logger.error("The config file must contain an 'interaction' key.")
                    sys.exit(-1)
                if "path" in config_data["interaction"]:
                    logger.debug(
                        "Updating the script path in '%s' from '%s' to 'lib%s.script.so'",
                        config,
                        config_data["interaction"]["path"],
                        load_library_name,
                    )
                config_data["interaction"]["path"] = f"{load_library_name}.script.so"
                with open(
                    lib_arch_dir.joinpath(f"{load_library_name}.config.so"), "w"
                ) as f:
                    f.write(json.dumps(config_data, indent=4))
                del upload_files["config"]
        elif js:
            preset_config = make_preset_config("script", f"{load_library_name}.script.so")
            config_name = f"{load_library_name}.config.so"
            write_json(lib_arch_dir.joinpath(config_name), preset_config)
            logger.debug("Created the default script config file: %s", config_name)
            del upload_files["config"]
        elif config:
            logger.warning(
                "The '%s' config file was provided without the script file.", config
            )
            logger.warning(
                "To upload the script file to the APK, please provide the --js option."
            )
            with open(config, "r") as f:
                contents = f.read()
                config_data = json.loads(contents)
                if "interaction" not in config_data:
                    logger.error("The config file must contain an 'interaction' key.")
                    sys.exit(-1)
                interaction_type = config_data["interaction"].get("type")
                if interaction_type in ("script", "script-directory") and "path" not in config_data["interaction"]:
                    logger.error("The config file must contain a 'path' key.")
                    sys.exit(-1)
                if "path" in config_data["interaction"]:
                    logger.warning(
                        "The script file must be located at '%s' on your device",
                        config_data["interaction"]["path"],
                    )

        for file_type, file_path in upload_files.items():
            if file_path:
                file_path = Path(file_path)
                if not file_path.exists():
                    logger.error("Frida %s file not found: %s", file_type, file_path)
                    sys.exit(-1)
                else:
                    target_name = f"{load_library_name}.{file_type}.so"
                    if file_path.name == target_name:
                        logger.debug(
                            "Uploading Frida %s file: %s", file_type, file_path.name
                        )
                    else:
                        logger.debug(
                            "Renaming and uploading Frida %s file: %s -> %s",
                            file_type,
                            file_path.name,
                            target_name,
                        )
                    shutil.copy(file_path, lib_arch_dir.joinpath(target_name))

    return insert_loadlibary(decompiled_path, main_activity, load_library_name)


def sign_apk(apk_path: str, ks: str = None, ks_alias: str = None, ks_key_pass: str = None, ks_pass: str = None):
    """Run uber apk signer with option

    Args:
        apk_path (str): path of apk file
        ks (str): keystore file path
        ks_alias (str): keystore alias
        ks_key_pass (str): key password
        ks_pass (str): keystore password
    """
    signer_path = download_signer()  # Download apk signer

    pipe = subprocess.PIPE
    cmd = ["java", "-jar", signer_path, "--apks", apk_path]

    if ks:
        cmd.append("--ks")
        cmd.append(ks)
    if ks_alias:
        cmd.append("--ksAlias")
        cmd.append(ks_alias)
    if ks_key_pass:
        cmd.append("--ksKeyPass")
        cmd.append(ks_key_pass)
    if ks_pass:
        cmd.append("--ksPass")
        cmd.append(ks_pass)

    with subprocess.Popen(
        cmd, stdin=pipe, stdout=subprocess.PIPE, stderr=sys.stderr
    ) as process:
        stdout, _ = process.communicate(b"\n")
        if process.returncode != 0:
            logger.error("The APK signing process failed.")
            raise subprocess.CalledProcessError(
                process.returncode, cmd, sys.stdout, sys.stderr
            )

        output = stdout.decode()
        print(output)
        if "VERIFY" in output:
            verify_message = output.split("VERIFY")[1]
            if "file:" in verify_message:
                apk_path = verify_message.split("file:")[1].split("\n")[0].strip()
                logger.info("APK signing finished: %s", apk_path)


def detect_adb_arch():
    """Detect the architecture of the currently connected device via ADB.

    This function communicates with a connected Android device over ADB
    to determine its CPU architecture (e.g., arm64-v8a, armeabi-v7a, x86).

    Returns:
        str: The detected architecture of the connected device.
              Defaults to 'arm64' if detection fails.
    """
    pipe = subprocess.PIPE
    cmd = ["adb", "shell", "getprop", "ro.product.cpu.abi"]
    default_arch = "arm64"

    try:
        with subprocess.Popen(
            cmd, stdin=pipe, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                logger.warning(
                    "Failed to execute ADB command. Error: %s", stderr.decode().strip()
                )
                logger.warning("Falling back to default architecture: %s", default_arch)
                return default_arch

            arch = stdout.decode().strip()
            if not arch:
                logger.warning(
                    "Architecture detection failed: no output received. Falling back to default: %s",
                    default_arch,
                )
                return default_arch

            if arch == "arm64-v8a":
                arch = "arm64"
            elif arch == "armeabi-v7a":
                arch = "arm"

            logger.info("Auto-detected architecture via ADB: %s", arch)
            return arch

    except FileNotFoundError:
        logger.warning(
            "ADB is not installed or not found in the system PATH. Falling back to default: %s",
            default_arch,
        )
        return default_arch
    except Exception as e:
        logger.warning(
            "An unexpected error occurred during architecture detection: %s. Falling back to default: %s",
            str(e),
            default_arch,
        )
        return default_arch


def print_version(ctx, _, value):
    """Print version and exit"""
    if not value or ctx.resilient_parsing:
        return
    print(f"frida-gadget version {__version__}")
    ctx.exit()


def wrap_js_with_timeout(js_content: str, delay: int) -> str:
    """Wrap JavaScript content with setTimeout

    Args:
        js_content (str): Original JavaScript content
        delay (int): Seconds to wait before executing

    Returns:
        str: Wrapped JavaScript content
    """
    return f"""setTimeout(function() {{
{js_content}
}}, {delay * 1000});"""


# pylint: disable=too-many-arguments
@click.command()
@click.option(
    "--arch",
    default=None,
    help="Specify the target architecture of the device. (options: arm64, x86_64, arm, x86, multi-arch)",
)
@click.option("--config", help="Specify the Frida configuration file.")
@click.option("--js", default=None, help="Specify the Frida gadget JavaScript file.")
@click.option(
    "--js-delay",
    type=int,
    help="Specify seconds to wait before executing the JavaScript file.",
)
@click.option(
    "--force-manifest",
    is_flag=True,
    help="Force modify AndroidManifest.xml even if it already has required permissions.",
)
@click.option(
    "--custom-gadget-name",
    default=None,
    help="Specify a custom name for the Frida gadget.",
)
@click.option("--no-res", is_flag=True, help="Skip decoding resources.")
@click.option(
    "--main-activity", default=None, help="Specify the main activity if known."
)
@click.option(
    "--sign", is_flag=True, help="Automatically sign the APK using uber-apk-signer."
)
@click.option("--skip-decompile", is_flag=True, help="Skip the decompilation step.")
@click.option("--skip-recompile", is_flag=True, help="Skip the recompilation step.")
@click.option(
    "--use-aapt2",
    is_flag=True,
    help="Use aapt2 instead of aapt for resource processing.",
)
@click.option(
    "--decompile-opts",
    default=None,
    help="Specify additional options for apktool decompile.",
)
@click.option(
    "--recompile-opts",
    default=None,
    help="Specify additional options for apktool recompile.",
)
@click.option(
    "--apktool-path", default=None, help="Specify the path or command to run apktool."
)
@click.option("--frida-version", default=None, help="Specify the Frida version to use.")
@click.option("--local-gadget", default=None, help="Use a local libfrida-gadget.so instead of downloading one.")
@click.option("--preset", type=click.Choice(PRESETS), default=None, help="Use a simple built-in Gadget config preset.")
@click.option("--output-dir", default=None, help="Copy the patched APK to this folder.")
@click.option("--backup", is_flag=True, help="Copy the original APK to a backup folder before patching.")
@click.option("--doctor", is_flag=True, help="Check local tools and exit.")
@click.option("--init-config", type=click.Choice(PRESETS), default=None, help="Write a preset Gadget config JSON and exit.")
@click.option("--dump", default=None, help="Run local frida-dexdump against this Android package and exit.")
@click.option("--dump-output", default=None, help="Output folder for --dump.")
@click.option("--deep-dump", is_flag=True, help="Use frida-dexdump deep search mode with --dump.")
@click.option("--dump-maps", is_flag=True, help="Save runtime memory maps beside DEX dumps.")
@click.option("--inspect-apk", type=click.Path(exists=True), default=None, help="Inspect an APK and print auto-detected JSON.")
@click.option("--ks", default=None, help="The keystore file. If not provided, will use debug keystore.")
@click.option("--ks-alias", default=None, help="The alias of the used key in the keystore.")
@click.option("--ks-key-pass", default=None, help="The password for the key.")
@click.option("--ks-pass", default=None, help="The password for the keystore.")
@click.option(
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Show the version and exit.",
)
@click.argument("apk_path", type=click.Path(exists=True), required=False)
def run(
    apk_path: str,
    arch: str,
    config: str,
    no_res: bool,
    main_activity: str,
    sign: bool,
    custom_gadget_name: str,
    js: str,
    js_delay: int,
    force_manifest: bool,
    skip_decompile: bool,
    skip_recompile: bool,
    use_aapt2: bool,
    decompile_opts: str,
    recompile_opts: str,
    apktool_path: str,
    frida_version: str,
    local_gadget: str,
    preset: str,
    output_dir: str,
    backup: bool,
    doctor: bool,
    init_config: str,
    dump: str,
    dump_output: str,
    deep_dump: bool,
    dump_maps: bool,
    inspect_apk: str,
    ks: str,
    ks_alias: str,
    ks_key_pass: str,
    ks_pass: str,
):
    """Patch an APK with the Frida gadget library"""
    if inspect_apk:
        click.echo(json.dumps(globals()["inspect_apk"](inspect_apk), indent=4))
        return

    if doctor:
        run_doctor(apktool_path)
        return

    if init_config:
        output = Path("frida-gadget.config.json").resolve()
        write_json(output, make_preset_config(init_config))
        logger.info("Wrote %s preset config: %s", init_config, output)
        return

    if dump:
        run_dumper(dump, dump_output, deep_dump, dump_maps)
        return

    if not apk_path:
        raise click.UsageError("Missing APK_PATH. Use --doctor, --init-config, or --dump for non-patching tasks.")

    apk_path = Path(apk_path)

    logger.info("APK: '%s'", apk_path)
    if arch is None:
        arch = detect_adb_arch()
    elif arch.lower() == "multi-arch":
        if skip_decompile:
            logger.warning(
                "The 'multi-arch' option requires decompiling the APK first to detect architectures"
            )
        arch = "multi-arch"
    elif arch == "arm64-v8a":
        arch = "arm64"
    elif arch == "armeabi-v7a":
        arch = "arm"

    # Validate js-delay option
    if js_delay is not None:
        if js is None:
            logger.error("The --js-delay option requires --js option to be specified.")
            sys.exit(-1)
        if js_delay < 0:
            logger.error("Delay value must be a positive number.")
            sys.exit(-1)
        logger.info("JavaScript execution will be delayed by %d seconds", js_delay)

    # Process JavaScript file with delay if specified
    if js and js_delay is not None:
        js_path = Path(js)
        if not js_path.exists():
            logger.error("The specified JavaScript file does not exist: %s", js)
            sys.exit(-1)

        try:
            original_content = js_path.read_text()
            wrapped_content = wrap_js_with_timeout(original_content, js_delay)

            # Create a temporary file with wrapped content
            temp_js = js_path.parent / f"{js_path.stem}_wrapped{js_path.suffix}"
            temp_js.write_text(wrapped_content)
            js = str(temp_js)
            logger.debug("Created wrapped JavaScript file: %s", js)
        except Exception as e:
            logger.error("Failed to process JavaScript file: %s", str(e))
            sys.exit(-1)

    global APKTOOL
    if apktool_path:
        APKTOOL = apktool_path
        apktool_parts = APKTOOL.split()
        apktool_binary = apktool_parts[-1]
        if not Path(apktool_binary).exists():
            logger.error(
                "The specified apktool path does not exist: %s", apktool_binary
            )
            sys.exit(-1)

        if len(apktool_parts) > 1:
            logger.info("Using custom apktool command: '%s'", APKTOOL)
        else:
            logger.info("Using custom apktool path: '%s'", APKTOOL)
    else:
        if not APKTOOL:
            raise FileNotFoundError(
                "apktool not found. Please install apktool and add it to your PATH environment.\n"
                "For macOS: brew install apktool\n"
                "For Windows: Download from https://ibotpeaches.github.io/Apktool/install/\n"
                "For Linux: sudo apt-get install apktool\n"
                "After installation, you may need to restart your terminal."
            )

    if arch != "multi-arch":
        logger.info(
            "Gadget Architecture(--arch): %s%s",
            arch,
            "(default)" if arch == "arm64" else "",
        )
    else:
        logger.info(
            "Gadget Architecture(--arch): %s (will inject for all architectures found in APK)",
            arch,
        )

    if js and not Path(js).exists():
        logger.error("The specified JavaScript file does not exist: %s", js)
        sys.exit(-1)

    if config and not Path(config).exists():
        logger.error("The specified configuration file does not exist: %s", config)
        sys.exit(-1)
    elif config:
        try:
            with open(config, "r") as f:
                json.load(f)
        except json.JSONDecodeError:
            logger.error(
                "The specified configuration file is not a valid JSON: %s", config
            )
            sys.exit(-1)

    if preset and preset == "script" and not js:
        logger.error("--preset script requires --js.")
        sys.exit(-1)

    if backup:
        backup_dir = apk_path.parent.joinpath("backup")
        backup_dir.mkdir(exist_ok=True)
        backup_path = backup_dir.joinpath(apk_path.name)
        shutil.copy2(apk_path, backup_path)
        logger.info("Backed up original APK: %s", backup_path)

    if arch != "multi-arch":
        arch = arch.lower()
        if arch not in SUPPORTED_ARCHS:
            logger.error(
                "The --arch option only supports the following architectures: %s, multi-arch",
                ", ".join(SUPPORTED_ARCHS),
            )
            sys.exit(-1)

    # Make temp directory for decompile
    decompiled_path = TEMP_DIR.joinpath(str(apk_path.resolve())[:-4])
    if not skip_decompile:
        logger.debug('Decompiling the target APK using apktool\n"%s"', decompiled_path)
        if decompiled_path.exists():
            shutil.rmtree(decompiled_path)
        decompiled_path.mkdir()

        # APK decompile with apktool
        decompile_option = ["d", "-o", str(decompiled_path.resolve()), "--force"]
        if force_manifest:
            decompile_option += ["--force-manifest"]
        if no_res:
            decompile_option += ["--no-res"]
        if decompile_opts:
            if "--no-res" in decompile_opts:
                if no_res:
                    # remove no-res option if it's already in the list
                    decompile_option.remove("--no-res")
                no_res = True
            decompile_option += decompile_opts.split()

        run_apktool(decompile_option, str(apk_path.resolve()))
    else:
        if not decompiled_path.exists():
            logger.error("Decompiled directory not found: %s", decompiled_path)
            sys.exit(-1)

    # Process if decompile is success
    modified_dex_number = inject_gadget_into_apk(
        apk_path,
        arch,
        decompiled_path,
        no_res,
        force_manifest,
        main_activity,
        config,
        js,
        custom_gadget_name,
        frida_version,
        local_gadget,
        preset,
    )

    # Rebuild with apktool, print apk_path if process is success
    if not skip_recompile:
        logger.debug('Recompiling the new APK using apktool "%s"', decompiled_path)

        recompile_option = ["b"]
        if use_aapt2:
            recompile_option += ["--use-aapt2"]
        if recompile_opts:
            recompile_option += recompile_opts.split()

        run_apktool(recompile_option, str(decompiled_path.resolve()))
        recompiled_apk_path = decompiled_path.joinpath("dist", apk_path.name)
        if not recompiled_apk_path.exists():
            logger.error("APK not found: %s", recompiled_apk_path)
        else:
            logger.info("Frida gadget injected into APK: %s", recompiled_apk_path)
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                copied_apk = output_path.joinpath(recompiled_apk_path.name)
                shutil.copy2(recompiled_apk_path, copied_apk)
                logger.info("Copied patched APK to: %s", copied_apk)

        # Clean up wrapped JavaScript file if it exists
        if js and js_delay is not None:
            temp_js = Path(js)
            if temp_js.exists() and temp_js.name.endswith("_wrapped.js"):
                try:
                    temp_js.unlink()
                    logger.debug("Cleaned up wrapped JavaScript file: %s", temp_js)
                except Exception as e:
                    logger.warning(
                        "Failed to clean up wrapped JavaScript file: %s", str(e)
                    )

        # Copy original dex files except the modified one to the recompiled APK
        logger.debug(f"Copying original dex files (except modified one {modified_dex_number}) to the recompiled APK")
        try:
            # Create a temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_dir_path = Path(temp_dir)

                # Extract original APK
                original_apk_zip = zipfile.ZipFile(apk_path, 'r')
                original_apk_zip.extractall(temp_dir_path)
                original_apk_zip.close()

                # Create a temporary file for the recompiled APK
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file_path = Path(temp_file.name)

                # Open recompiled APK for reading
                recompiled_apk = zipfile.ZipFile(recompiled_apk_path, 'r')

                # Create a new ZIP file
                new_apk = zipfile.ZipFile(temp_file_path, 'w')

                # Copy all files from recompiled APK except dex files
                modified_dex_filename = f"classes{modified_dex_number}.dex" \
                    if modified_dex_number and modified_dex_number > 1 else "classes.dex"

                for item in recompiled_apk.infolist():
                    if item.filename == modified_dex_filename:
                        logger.debug(f"Copying {item.filename} from recompiled APK")
                        new_apk.writestr(item, recompiled_apk.read(item.filename))
                    elif item.filename.startswith('classes') and item.filename.endswith('.dex'):
                        dex_file = temp_dir_path.joinpath(item.filename)
                        new_apk.write(str(dex_file), dex_file.name)
                    else:
                        new_apk.writestr(item, recompiled_apk.read(item.filename))

                # Close all zip files
                recompiled_apk.close()
                new_apk.close()

                # Replace the recompiled APK with the new one
                shutil.move(temp_file_path, recompiled_apk_path)
                logger.info("Successfully replaced dex files in the recompiled APK")
        except Exception as e:
            logger.error(f"Failed to copy original dex files: {str(e)}")

        if sign:
            logger.debug("Starting APK signing using uber-apk-signer")
            sign_apk(str(recompiled_apk_path), ks, ks_alias, ks_key_pass, ks_pass)
            return
    else:
        logger.info(apk_path)
    logger.warning(
        "The APK is not signed. Use the --sign option to sign it automatically, "
        "or sign the APK manually before installing it."
    )


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    run()
