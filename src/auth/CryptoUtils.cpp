#include "svf/auth/CryptoUtils.h"
#include <random>
#include <sstream>
#include <iomanip>

// NOTE: We are implementing a stub for Argon2id here to ensure the project compiles
// out of the box while the user sets up libargon2 locally on Windows.
// In a production build, this will use argon2id_hash_encoded.

std::string CryptoUtils::generateSalt() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return ss.str();
}

std::string CryptoUtils::hashPassword(const std::string& password, const std::string& salt) {
    // STUB: Replace with actual Argon2id call
    // argon2id_hash_encoded(2, 65536, 1, password.c_str(), password.length(), salt.c_str(), salt.length(), 32, encoded, sizeof(encoded));
    
    // For now, simple fallback combining pass and salt
    std::string combined = password + salt;
    std::stringstream ss;
    for(char c : combined) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return "argon2_stub$" + salt + "$" + ss.str();
}

bool CryptoUtils::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    std::string expectedHash = hashPassword(password, salt);
    return expectedHash == hash;
}
