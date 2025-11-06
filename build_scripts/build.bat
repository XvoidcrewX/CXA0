@echo off
echo Building CXA for Windows...

python --version >nul 2>&1
if errorlevel 1 (
    echo Python is required but not installed.
    pause
    exit /b 1
)

pip install --upgrade pip
pip install cryptography>=41.0.0
pip install numpy>=1.21.0
pip install Pillow>=9.0.0
pip install PyWavelets>=1.1.0
pip install zstandard>=0.15.0
pip install psutil>=5.8.0
pip install keyring>=23.0.0
pip install reedsolo>=1.7.0
pip install secretsharing>=0.2.7
pip install pycryptodome>=3.10.0
pip install cffi>=1.15.0
pip install pyinstaller

pyinstaller --onefile --name="CXA" --icon="assets/icon.ico" src/main.py

echo Build complete. Executable: dist\CXA.exe
pause
