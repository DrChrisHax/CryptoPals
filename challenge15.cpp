/*
PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
*/
#include "challenges.h"
#include "encoding_utils.h"

std::string challenge15() {
	const std::string validPadding = "ICE ICE BABY\x04\x04\x04\x04";
	const std::string invalidPadding1 = "ICE ICE BABY\x05\x05\x05\x05";
	const std::string invalidPadding2 = "ICE ICE BABY\x01\x02\x03\x04";

	std::ostringstream result;

	auto testUnpad = [&](const std::string& input, const std::string& label) {
		try {
			std::string upadded = unpadPKCS7WithErrors(input);
			result << label << ": Unpadded successfully!\n";
		}
		catch (const std::exception& e) {
			result << label << " : Unpad failed! Error - " << e.what() << "\n";
		}
	};

	testUnpad(validPadding, "Valid PKCS7 String");
	testUnpad(invalidPadding1, "Invalid PKCS7 String 1");
	testUnpad(invalidPadding2, "Invalid PKCS7 String 2");

	return result.str();
}