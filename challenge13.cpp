/*
ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
*/

#include "challenges.h"
#include "encoding_utils.h"
#include "random.h"
#include "aes.h"

const std::string key = GenerateRandomBytes(16);

std::string profile_for(const std::string& email) {
    std::string cleanEmail;
    for (char c : email) {
        if (c == '&' || c == '=') continue;
        cleanEmail.push_back(c);
    }
    return aes_128_ecb_encrypt("email=" + cleanEmail + "&uid=10&role=user", key);
}

std::map<std::string, std::string> decryptProfile(const std::string& ciphertext) {
    std::string decrypted = aes_128_ecb_decrypt(ciphertext, key);
    return parseKV(decrypted);
}

std::string challenge13() {
    std::string normalEmail = "AAAA@test.com";
    std::string normalCiphertext = profile_for(normalEmail);
    std::vector<std::string> normalBlocks = splitBlocks(normalCiphertext, 16);

    std::string admin = "admin";
    std::string adminPadded = padPKCS7(admin, 16);

    std::string attackerEmail = "A@test.com" + adminPadded;
    std::string attackCiphertext = profile_for(attackerEmail);
    std::vector<std::string> attackerBlocks = splitBlocks(attackCiphertext, 16);

    std::string forgedCiphertext = normalBlocks[0] + normalBlocks[1] + attackerBlocks[1];

    std::map<std::string, std::string> profile = decryptProfile(forgedCiphertext);

    std::string output = "";

    for (const auto& pair : profile) {
        output += pair.first + ": " + unpadPKCS7(pair.second) + "\n";
    }
    return output;
}