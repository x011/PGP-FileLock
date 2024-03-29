# PGP FileLock

PGP FileLock is a lightweight tool for encrypting and decrypting files using PGP standards. It provides a simple interface for generating PGP key pairs, encrypting files with public keys, and decrypting them with private keys. Designed for users who need quick and secure file encryption without the complexity of full-featured PGP software.

## Features

- Generate PGP key pairs with customizable key sizes and expiration dates.
- Encrypt files using PGP public keys.
- Decrypt files using PGP private keys and associated passphrases.
- Simple and intuitive Graphical User Interface (GUI) for ease of use.
- Command Line Interface (CLI) for automation and scripting.
- Cross-platform support for Windows, macOS, and Linux.

## Installation

Clone the repository or download the source code:

```
git clone https://github.com/x011/PGP-FileLock.git
cd PGP-FileLock
pip install -r requirements.txt
```

Ensure you have Python 3 installed on your system. No additional installation steps are required as the tool is a standalone Python script.

## Usage


### Download Precompiled Binaries

For added convenience, precompiled binaries for Windows, Linux and macOS are available for [download](https://github.com/x011/PGP-FileLock/releases/).

### GUI Mode

To use PGP FileLock in GUI mode, simply run the script without any arguments:

```
python3 pgp_filelock.py
```

The GUI will launch, allowing you to generate keys, encrypt files, and decrypt files using a user-friendly interface.

### CLI Mode

PGP FileLock can also be operated via the command line, providing a way to integrate PGP encryption and decryption into your workflows.

#### Generate Keys (All Options)

```
python3 pgp_filelock.py generate --name "Your Name" --email "your.email@example.com" --expire-years 2 --key-size 4096 --passphrase "YourPassphrase" --private-key-file "private_key.asc" --public-key-file "public_key.asc" --overwrite
```

#### Generate Keys (Required Options Only)

```
python3 pgp_filelock.py generate --name "Your Name" --email "your.email@example.com"
```

#### Encrypt File (All Options)

```
python3 pgp_filelock.py encrypt --file "path/to/your/file.txt" --public-key-file "public_key.asc" --output "encrypted_file.pgp" --overwrite
```

#### Encrypt File (Required Options Only)

```
python3 pgp_filelock.py encrypt --file "path/to/your/file.txt" --public-key-file "public_key.asc"
```

#### Decrypt File (All Options)

```
python3 pgp_filelock.py decrypt --file "encrypted_file.pgp" --private-key-file "private_key.asc" --passphrase "YourPassphrase" --output "decrypted_file.txt" --overwrite
```

#### Decrypt File (Required Options Only)

```
python3 pgp_filelock.py decrypt --file "encrypted_file.pgp" --private-key-file "private_key.asc"
```

## Screenshots

![2024-02-07_17h23_59](https://github.com/x011/PGP-FileLock/assets/4313821/0627b00b-a269-4eca-ba1e-4899b4146846)
![2024-02-07_17h25_15](https://github.com/x011/PGP-FileLock/assets/4313821/bbbfc22d-328e-4f45-a50c-c9d97eea67b0)


## Compiling Binaries

Before attempting to compile the binaries, please ensure the following prerequisites are met:

- PyInstaller is installed. If not, install it using pip:
  ```
  pip install pyinstaller
  ```
- Ensure that the required image files (`key.png`, `lock.png`, `unlock.png`) and the icon file (`lock.ico`) are located in the script's directory, having been copied there from the `images` folder.

Once you have confirmed the prerequisites, use the following commands to compile the binaries for Windows and Linux:

### Windows

```
pyinstaller --onefile --add-data "key.png;." --add-data "lock.png;." --add-data "unlock.png;." --clean --name pgp_filelock_1.0.0_x86_64-windows.exe --icon=lock.ico pgp_filelock.py
```

### Linux

```
pyinstaller --onefile --add-data "key.png:." --add-data "lock.png:." --add-data "unlock.png:." --clean --name pgp_filelock_1.0.0_x86_64-linux --icon=lock.ico pgp_filelock.py
```

## macOS

```
pyinstaller --onefile --add-data "key.png:." --add-data "lock.png:." --add-data "unlock.png:." --clean --name pgp_filelock_1.0.0_x86_64-macos.app --icon=lock.ico pgp_filelock.py
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, and suggest features.

## Support

If you need help or have any questions, please open an [issue](https://github.com/x011/PGP-FileLock/issues).

## License

PGP FileLock is licensed under the GNU General Public License v3.0 (GPL-3.0). For more information, please see the [LICENSE](LICENSE) file.
