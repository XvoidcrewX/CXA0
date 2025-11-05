@echo off
echo Building CXA Cryptographic System for Windows...

python --version >nul 2>&1
if errorlevel 1 (
    echo Python is required but not installed.
    pause
    exit /b 1
)

python -m venv build_env
call build_env\Scripts\activate.bat

pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

pyinstaller --onefile --name="CXA" --add-data="*.py;." --windowed --icon="assests/icon.ico" build_scripts/main.py

deactivate
rd /s /q build_env

echo Build complete. Executable: dist\CXA.exe
pause
