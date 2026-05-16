@echo off
cd /d "%~dp0frida-gadget-trunk"
python -m scripts.gui %*
