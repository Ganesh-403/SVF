#pragma once
#include <string>

class CryptoUtils {
public:
    // Generate a secure random salt
    static std::string generateSalt();
    
    // Hash password using Argon2id (requires libargon2)
    // High-performance password derivation interface
    static std::string hashPassword(const std::string& password, const std::string& salt);
    
    // Verify a password against a hash and salt
    static bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt);
};
