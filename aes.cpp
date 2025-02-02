#include "aes.h"
#include "encoding_utils.h"

std::string aes_128_ecb_encrypt(const std::string& data, const std::string& key) {
	if (key.size() != 16) {
		throw std::runtime_error("Key must be 16 bytes for AES-128");
	}

	std::string paddedData = padPKCS7(data, 16);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP context");
	}

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), nullptr)) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encryption initialization failed.");
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	std::string ciphertext;
	ciphertext.resize(paddedData.size() + EVP_CIPHER_block_size(EVP_aes_128_ecb()));

	int len = 0;
	int ciphertextLen = 0;

	if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
		reinterpret_cast<const unsigned char*>(paddedData.data()),
		static_cast<int>(paddedData.size()))) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encryption update failed");
	}
	ciphertextLen = len;

	if (1 != EVP_EncryptFinal(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encryption finalization failed");
	}
	ciphertextLen += len;

	EVP_CIPHER_CTX_free(ctx);

	ciphertext.resize(ciphertextLen);
	return ciphertext;
}

std::string aes_128_ecb_decrypt(const std::string& data, const std::string& key) {
	if (key.size() != 16) {
		throw std::runtime_error("Key must be 16 bytes for AES-128");
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP context");
	}

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), nullptr)) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Decryption initialization failed.");
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	std::string plaintext;
	plaintext.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_128_ecb()));

	int len = 0;
	int plaintextLen = 0;

	if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
		reinterpret_cast<const unsigned char*>(data.data()),
		static_cast<int>(data.size()))) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Decryption update failed");
	}
	plaintextLen = len;

	if (1 != EVP_DecryptFinal(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Decryption finalization failed");
	}
	plaintextLen += len;

	EVP_CIPHER_CTX_free(ctx);

	plaintext = unpadPKCS7(plaintext);

	plaintext.resize(plaintextLen);
	return plaintext;
}

std::string aes_128_cbc_encrypt(const std::string& data, const std::string& key, const std::string& iv, size_t blockSize) {
	std::string paddedData = padPKCS7(data, blockSize);
	std::vector<std::string> blocks = splitBlocks(data, blockSize);
	std::string prevBlock = iv;
	std::string ciphertext;
	ciphertext.reserve(data.size());

	for (const auto& block : blocks) {
		std::string xored = fixedXor(block, prevBlock);
		std::string encrypt = aes_128_ecb_encrypt(xored, key);
		ciphertext += encrypt;
		prevBlock = encrypt;
	}
	return ciphertext;
}

std::string aes_128_cbc_decrypt(const std::string& data, const std::string& key, std::string iv, size_t blockSize) {
	std::vector<std::string> blocks = splitBlocks(data, blockSize);
	std::string paddedPlaintext;

	for (const auto& block : blocks) {
		std::string decrypt = aes_128_ecb_decrypt(block, key);
		decrypt = fixedXor(decrypt, iv);
		paddedPlaintext += decrypt;
		iv = block;
	}
	return unpadPKCS7(paddedPlaintext);
}

