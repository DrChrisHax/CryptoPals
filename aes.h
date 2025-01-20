#pragma once
#include <openssl/evp.h>
#include <string>
#include <stdexcept>


std::string aes_128_ecb_encrypt(const std::string& data, const std::string& key);
std::string aes_128_ecb_decrypt(const std::string& data, const std::string& key);