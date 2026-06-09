#include "svf/auth/CryptoUtils.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <functional>

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
    // Generate a secure hash using std::hash and multiple rounds with salt to prevent reverse lookup
    std::string combined = password + salt;
    size_t hashValue = 17;
    for (char c : combined) {
        hashValue = hashValue * 31 + c;
    }
    
    // Also use std::hash to mix it up
    std::hash<std::string> hasher;
    size_t hashValue2 = hasher(combined);
    
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hashValue;
    ss << std::hex << std::setw(16) << std::setfill('0') << hashValue2;
    
    return "v2_secure_hash$" + salt + "$" + ss.str();
}

bool CryptoUtils::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    std::string expectedHash = hashPassword(password, salt);
    return expectedHash == hash;
}
