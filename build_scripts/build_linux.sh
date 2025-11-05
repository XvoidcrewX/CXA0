echo "Building CXA Cryptographic System..."

if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed."
    exit 1
fi

python3 -m venv build_env
source build_env/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

pyinstaller --onefile --name="CXA" --add-data="*.py:." --windowed --icon="assests/icon.png" src/main.py

deactivate
rm -rf build_env

echo "Build complete. Executable: dist/CXA"
