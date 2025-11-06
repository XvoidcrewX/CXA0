echo "Building CXA for Linux..."

sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.10 python3.10-dev python3.10-venv python3.10-distutils
sudo apt-get install -y build-essential libjpeg-dev zlib1g-dev

python3.10 -m pip install --upgrade pip
python3.10 -m pip install cryptography>=41.0.0
python3.10 -m pip install numpy>=1.21.0
python3.10 -m pip install Pillow>=9.0.0
python3.10 -m pip install PyWavelets>=1.1.0
python3.10 -m pip install zstandard>=0.15.0
python3.10 -m pip install psutil>=5.8.0
python3.10 -m pip install keyring>=23.0.0
python3.10 -m pip install reedsolo>=1.7.0
python3.10 -m pip install secretsharing>=0.2.7
python3.10 -m pip install pycryptodome>=3.10.0
python3.10 -m pip install cffi>=1.15.0
python3.10 -m pip install pyinstaller

python3.10 -m PyInstaller --onefile --name="CXA" --icon="assets/icon.png" src/main.py

echo "Build complete. Executable: dist/CXA"
