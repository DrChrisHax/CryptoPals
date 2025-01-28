#include "print_utils.h"

std::string formatAsPrintable(const std::string& input) {
	std::ostringstream oss;

	for (unsigned char c : input) {
		if (isprint(c)) {
			oss << c;
		}
		else {
			oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)(c);
		}
	}
	return oss.str();
}