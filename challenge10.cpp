/*
Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
Don't cheat.

Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?
*/

#include "challenges.h"
#include "encoding_utils.h"
#include "aes.h"
#include "print_utils.h"

std::string challenge10() {

	const std::string key = "YELLOW SUBMARINE";
	const std::string iv(16, '\0');

	std::ifstream file("10.txt");
	if (!file.is_open()) {
		return "File 10.txt failed to open";
	}

	std::ostringstream buffer;
	buffer << file.rdbuf();

	std::string data = base64ToText(buffer.str());

	return aes_128_cbc_decrypt(data, key, iv, 16);
}