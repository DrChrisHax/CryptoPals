#pragma once
#include <openssl/evp.h>
#include <string>
#include <stdexcept>

std::string aes_128_ecb_encrypt(const std::string& data, const std::string& key);
std::string aes_128_ecb_decrypt(const std::string& data, const std::string& key);

std::string aes_128_cbc_encrypt(const std::string& data, const std::string& key, const std::string& iv, size_t blockSize);
std::string aes_128_cbc_decrypt(const std::string& data, const std::string& key, std::string iv, size_t blockSize);

using BlackBoxEncryptionFunc = std::string(*)(const std::string&);
int findECBBlockSize(BlackBoxEncryptionFunc BlackBoxEncryption);
bool isECBMode(int blockSize, BlackBoxEncryptionFunc BlackBoxEncryption);