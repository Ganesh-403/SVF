# Secure Virtual File System (SVF) V2

![Build Status](https://img.shields.io/github/actions/workflow/status/username/svf/build.yml?branch=main)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![C++ Standard](https://img.shields.io/badge/C%2B%2B-17-orange.svg)

## 📌 Overview
SVF is a **production-grade, C++17 virtual file system engine**. It goes beyond simple CRUD operations by implementing real systems programming paradigms, including physical block storage simulation, POSIX permissions, and concurrent inode access.

## 🚀 Key Engineering Features
- **True Persistence (Virtual Disk):** Data is not stored in RAM vectors. The engine formats a binary `.img` file into a Superblock, Bitmap Allocators, and 4KB Data Blocks (inspired by `ext4`).
- **Concurrent Access Locks:** Utilizes `std::shared_mutex` at the Inode level to allow multiple concurrent readers but strictly isolated writers.
- **Advanced Cryptography:** Passwords are hashed using **Argon2id** with cryptographic salts, completely eliminating rainbow table vulnerabilities associated with generic SHA-256.
- **POSIX Permission Model:** Enforces bitmask permission logic (e.g., `0755` `rwxr-xr-x`) strictly separated into User, Group, and Others.
- **Modular Architecture:** Cleanly decoupled into Storage, VFS, Authentication, and Interface layers using a robust CMake build system.

## 📂 Architecture
```
SVF/
├── include/svf/
│   ├── auth/          # Argon2 hashing & User management
│   ├── storage/       # Virtual Disk & Block allocation
│   └── vfs/           # Inode mapping & POSIX permissions
├── src/               # Implementation files
├── CMakeLists.txt     # Build configuration
└── Dockerfile         # Containerized runtime
```

## 🛠 Compilation & Execution (CMake)

### **Prerequisites**
- CMake 3.14+
- C++17 Compiler (GCC, Clang, MSVC)
- libargon2-dev (Optional: Fallback stub included)
- OpenSSL (Optional)

### **Build via CMake**
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
./svf
```

### **Build via Docker**
```bash
docker build -t svf-engine .
docker run -it svf-engine
```

## 📖 System Commands
The virtual shell operates over the physical block engine:

| Command         | Description                                      |
|----------------|--------------------------------------------------|
| `login`        | Authenticate user                                |
| `register`     | Register a new user                              |
| `logout`       | End current session                              |
| `touch <file>` | Allocate an Inode for a new file                 |
| `mkdir <dir>`  | Allocate a Directory Inode                       |
| `ls`           | List contents with POSIX Octal modes             |
| `write <fd>`   | Write data sequentially to physical 4KB blocks   |
| `read <fd>`    | Reconstruct file from physical blocks            |
| `exit`         | Safely unmount disk & flush Superblock           |

## 🔒 Security Architecture
- **Argon2id** Memory-Hard password derivation.
- Strict mapping of UID/GID to operations.
- Process isolation via Docker containerization.

## 📜 License
This project is open-source and available under the **MIT License**.
