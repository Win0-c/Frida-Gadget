# Frida Gadget
jewish modding methods right here
This folder is now split into three useful parts:

- `frida-gadget-trunk`: the Python APK patcher you already had.
- `frida-source`: the real Frida source tree. Gadget lives here:
  `frida-source/subprojects/frida-core/lib/gadget/gadget.vala`
- `frida-dexdump`: a Frida-based Android DEX dumper.

## First Files To Edit

Start with:

```text
frida-source/subprojects/frida-core/lib/gadget/gadget.vala
```

That is the main Gadget runtime logic. Good first changes:

- Add a custom startup log/banner so you can prove your build is running.
- Simplify config defaults so Gadget works with fewer files.
- Add a friendlier config option for loading a local script.
- Make connection/listening behavior easier to switch.

## Useful Commands

Show the helper menu:

```powershell
.\frida-workspace.bat
```

Find Gadget source files:

```powershell
.\frida-workspace.bat find-gadget
```

Run the dex dumper help:

```powershell
.\frida-workspace.bat dumper-help
```

## New Patcher Features

The APK patcher now has friendlier commands:

```powershell
cd .\frida-gadget-trunk
python -m scripts.cli --doctor
python -m scripts.cli --init-config listen
python -m scripts.cli --inspect-apk app.apk
python -m scripts.cli app.apk --preset listen --backup --output-dir output
python -m scripts.cli app.apk --local-gadget ..\custom\libfrida-gadget.so --preset listen
python -m scripts.cli --dump com.target.app --dump-output dumps --deep-dump --dump-maps
```

`--local-gadget` is the switch that lets the patcher use your own rebuilt Gadget instead of downloading the stock Frida release.

`--dump` uses the local `.venv-dexdump` environment so the dumper dependencies stay isolated from your main Python install.

## GUI

Launch the simple desktop GUI from the main folder:

```powershell
.\Frida Gadget GUI.bat
```

Or from inside the patcher folder:

```powershell
.\frida-gadget-gui.bat
```

The GUI wraps the same CLI options: patch APK, run doctor, create config, open the real Gadget source, and run the DEX dumper.

You can drag an APK onto the open GUI window, or drag an APK directly onto:

```powershell
.\Frida Gadget GUI.bat
```

When an APK is loaded, the GUI auto-detects package name, main activity, native architectures, best arch setting, output folders, and warnings like existing Gadget or split/config APKs.

DEX dumping now enables maps by default. This writes `maps.json` and `maps.txt` beside dumped DEX files so you can compare each dump against runtime memory ranges.

## Build Notes

Building real Frida Gadget for Android is heavier than editing the APK patcher. The official build starts from:

```powershell
cd .\frida-source
.\configure.bat
```

The next clean improvement is to make a tiny Gadget change, build it, and then update the Python patcher so it uses your custom `libfrida-gadget.so` instead of downloading stock releases.
