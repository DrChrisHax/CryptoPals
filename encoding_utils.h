#pragma once

#include <string>
#include <cctype>
#include <vector>
#include <bitset>
#include <algorithm>
#include <unordered_set>

std::string textToHex(const std::string& input);
std::string hexToText(const std::string& input);
std::string textToBase64(const std::string& input);
std::string base64ToText(const std::string& input);

std::string fixedXor(const std::string& input1, const std::string& input2);
std::string repeatingXor(const std::string& input, const std::string& key);

int hammingDistance(const std::string& input1, const std::string& input2);

bool hasRepeatingBlocks(const std::string& ciphertext, size_t blockSize);

std::string padPKCS7(const std::string& plaintext, size_t blockSize);
std::string unpadPKCS7(const std::string& paddedtext);