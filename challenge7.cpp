/*
AES in ECB mode

The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
Do this with code.

You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
*/
#include "challenges.h"
#include "encoding_utils.h"
#include "aes.h"


std::string challenge7() {
	const std::string KEY = "YELLOW SUBMARINE";

    std::ifstream file("7.txt");
    if (!file.is_open()) {
        return "File 7.txt failed to open";
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();

    std::string data = base64ToText(buffer.str());

    return aes_128_ecb_decrypt(data, KEY);
}