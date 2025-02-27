# Secure Virtual File System (SVF)

## 📌 Overview
SVF (Secure Virtual File System) is a **C++-based** virtual file system that supports user authentication, file and directory management, access control, and secure password handling using **OpenSSL SHA-256 hashing**.

## 🚀 Features
- **User Authentication** (Admin, Normal User, Read-Only)
- **File & Directory Management** (Create, Delete, Open, Read, Write)
- **Access Control** (Permission-Based File Access)
- **Secure Password Handling** (SHA-256 Hashing)
- **Cross-Platform Compatibility** (Windows & Linux)

## 📂 File Structure
```
SVF/
│-- SVF.cpp       # Main source code
│-- README.md     # Documentation
│-- users.txt     # Stores user credentials (hashed passwords)
```

## 🛠 Prerequisites
- **C++ Compiler** (MinGW-w64 for Windows, g++ for Linux/macOS)
- **OpenSSL** (Ensure OpenSSL is installed & configured)

### 📥 Installing OpenSSL
#### **Windows**:
1. Download from [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html).
2. Install it to `C:\OpenSSL-Win64`.
3. Add `C:\OpenSSL-Win64\bin` to System `PATH`.

#### **Linux/macOS**:
```sh
sudo apt install openssl libssl-dev  # Debian-based
brew install openssl                 # macOS
```

## 🔧 Compilation & Execution
### **1. Compile the Code**
```sh
g++ -std=c++17 -o svf SVF.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib" -lssl -lcrypto
```

### **2. Run the Executable**
```sh
./svf   # On Linux/macOS
svf.exe   # On Windows
```

## 📖 Usage
After running the program, you can use the following commands:

| Command         | Description                                      |
|----------------|--------------------------------------------------|
| `login <user>` | Log in as a user                                |
| `register`     | Register a new user                             |
| `logout`       | Log out of the system                           |
| `touch <file>` | Create a new file                               |
| `mkdir <dir>`  | Create a new directory                         |
| `cd <dir>`     | Change the current directory                   |
| `ls`           | List directory contents                        |
| `open <file>`  | Open a file                                    |
| `write <fd>`   | Write to a file                                |
| `read <fd>`    | Read from a file                               |
| `close <fd>`   | Close an open file                             |
| `rm <file>`    | Delete a file                                  |
| `rmdir <dir>`  | Remove an empty directory                      |
| `whoami`       | Show current user details                      |
| `help`         | Show available commands                        |

## 🔒 Security Measures
- Passwords are **hashed using SHA-256** before storing.
- Admins can create, delete, and manage users.
- File access is **permission-based**.

## 🛠 Troubleshooting
### **OpenSSL Library Not Found**
If you see an error like:
```sh
cannot find -lssl: No such file or directory
```
Fix it by specifying OpenSSL paths:
```sh
g++ -std=c++17 -o svf SVF.cpp -I"C:\OpenSSL-Win64\include" -L"C:\OpenSSL-Win64\lib" -lssl -lcrypto
```

### **MinGW Not Recognized**
Ensure MinGW is installed and added to `PATH`.
```sh
gcc --version
```
If it's missing, reinstall MinGW from [Winlibs](https://winlibs.com/).

## 📜 License
This project is open-source and available under the **MIT License**.

## 🤝 Contributions
Contributions are welcome! Feel free to fork and submit pull requests.

---
✅ **Built with C++ & OpenSSL for Secure File Management**

