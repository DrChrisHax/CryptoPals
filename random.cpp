#include "random.h"

int RandomInt(int lowerBound, int upperBound) {
	if (!seeded) {
		std::srand(static_cast<unsigned int>(std::time(nullptr)));
		seeded = true;
	}
	return lowerBound + std::rand() % (upperBound - lowerBound + 1);
}

std::string GenerateRandomBytes(int len) {
	if (!seeded) {
		std::srand(static_cast<unsigned int>(std::time(nullptr)));
		seeded = true;
	}

	std::string randomBytes(len, 0);

	for (auto& byte : randomBytes) {
		byte = static_cast<char>(std::rand() % 256);
	}
	return randomBytes;
}

std::string GenerateRandomBytes(int lowerBound, int upperBound) {
	if (!seeded) {
		std::srand(static_cast<unsigned int>(std::time(nullptr)));
		seeded = true;
	}

	int length = lowerBound + std::rand() % (upperBound - lowerBound + 1);
	std::string randomBytes(length, 0);

	for (auto& byte : randomBytes) {
		byte = static_cast<char>(std::rand() % 256);
	}
	return randomBytes;
}