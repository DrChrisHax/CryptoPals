#include "encoding_utils.h"

static const std::string hex_chars = "0123456789abcdef";
static const std::string base64_chars = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";


std::string textToHex(const std::string& input) {
	std::string output;
	output.reserve(input.length() * 2);

	for (unsigned char c : input) {
		output.push_back(hex_chars[c >> 4]);
		output.push_back(hex_chars[c & 0x0F]);
	}
	return output;
}

std::string hexToText(const std::string& input) {
	if (input.size() % 2 != 0) {
		return "";
	}

	for (char c : input) {
		if (!std::isxdigit(static_cast<unsigned char>(c))) {
			return "";
		}
	}

	std::string output;
	output.reserve(input.size() / 2);

	for (size_t i = 0; i < input.size(); i += 2) {
		char highNibble = input[i];
		char lowNibble = input[i + 1];

		int byte =
			(std::isdigit(highNibble) ? highNibble - '0' : std::tolower(static_cast<unsigned char>(highNibble)) - 'a' + 10) << 4
			|
			(std::isdigit(lowNibble) ? lowNibble - '0' : std::tolower(static_cast<unsigned char>(lowNibble)) - 'a' + 10);

		output.push_back(static_cast<char>(byte));
	}
	return output;
}

std::string textToBase64(const std::string& input) {
	std::string output;
	output.reserve(((input.size() + 2) / 3) * 4);


	for (size_t i = 0; i < input.size(); i += 3) {
		uint32_t threeBytes = 0;
		size_t bytesToProcess = 0;

		for (size_t j = 0; j < 3; j++) {
			if (i + j < input.size()) {
				threeBytes |= (static_cast<uint8_t>(input[i + j]) << (16 - 8 * j));
				bytesToProcess++;
			}
		}

		for (size_t k = 0; k < 4; k++) {
			if (k <= bytesToProcess) {
				uint8_t sixBits = (threeBytes >> (18 - 6 * k)) & 0x3F;
				output.push_back(base64_chars[sixBits]);
			}
			else {
				output.push_back('=');
			}
		}
	}
	return output;
}

std::string base64ToText(const std::string& input) {
	std::vector<int> decodeTable(256, -1);
	for (size_t i = 0; i < 64; i++) {
		decodeTable[static_cast<unsigned char>(base64_chars[i])] = i;
	}

	std::string output;
	output.reserve(((input.size() + 3) / 4) * 3);

	int bitsCollected = 0;
	unsigned int accumulator = 0;

	for (unsigned char c : input) {
		if (c == '=') { break; }

		int decodedValue = (c < 256) ? decodeTable[c] : -1;
		if (decodedValue == -1) { continue; }

		accumulator = (accumulator << 6) | decodedValue;
		bitsCollected += 6;

		if (bitsCollected >= 8) {
			bitsCollected -= 8;
			unsigned char byte = static_cast<unsigned char>((accumulator >> bitsCollected) & 0xFF);
			output.push_back(byte);
		}
	}
	return output;
}

std::string fixedXor(const std::string& input1, const std::string& input2) {
	if (input1.size() != input2.size()) { return ""; }

	std::string output;
	output.reserve(input1.size());

	for (size_t i = 0; i < input1.size(); i++) {
		output.push_back((input1[i]) ^ (input2[i]));
	}
	return output;
}

std::string repeatingXor(const std::string& input, const std::string& key) {
	size_t inputSize = input.size(), keySize = key.size();

	std::string output;
	output.reserve(inputSize);

	for (size_t p = 0; p < inputSize; p++) {
		output.push_back(input[p] ^ key[p % keySize]);
	}

	return output;
}