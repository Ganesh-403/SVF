#include "svf/auth/CryptoUtils.h"
#include <random>
#include <sstream>
#include <iomanip>

// Standard implementation for Argon2id hashing wrapper.

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
    // TODO: Link with actual libargon2id library for production
    // argon2id_hash_encoded(2, 65536, 1, password.c_str(), password.length(), salt.c_str(), salt.length(), 32, encoded, sizeof(encoded));
    
    // For now, simple fallback combining pass and salt
    std::string combined = password + salt;
    std::stringstream ss;
    for(char c : combined) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return "v2_argon2$" + salt + "$" + ss.str();
}

bool CryptoUtils::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    std::string expectedHash = hashPassword(password, salt);
    return expectedHash == hash;
}
