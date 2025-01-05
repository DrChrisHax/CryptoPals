#pragma once

#include <string>
#include <cctype>
#include <vector>

std::string textToHex(const std::string& input);
std::string hexToText(const std::string& input);
std::string textToBase64(const std::string& input);
std::string base64ToText(const std::string& input);

std::string fixedXor(const std::string& input1, const std::string& input2);