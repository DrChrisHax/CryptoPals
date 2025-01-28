#include "challenges.h"
#include "encoding_utils.h"
#include "print_utils.h"




std::string challenge9() {
	const std::string plaintext = "YELLOW SUBMARINE";

	std::string paddedtext = padPKCS7(plaintext, 20);

	return formatAsPrintable(unpadPKCS7(paddedtext));
}