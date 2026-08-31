
#include <iostream>
#include <vector>
#include <string>

#include "aes_utils.h"

int main()
{
    // Test AES key
    aesgcm::Key key{};

    for (int i = 0; i < aesgcm::KEY_LEN; i++)
        key[i] = static_cast<unsigned char>(i);

    // Original message
    std::string message =
        "Hello, this message will be tampered with.";

    std::cout << "Original message:\n";
    std::cout << message << "\n\n";


    // Encrypt
    std::vector<unsigned char> packet =
        aesgcm::encrypt(key, message);

    std::cout << "Encrypted packet size: "
              << packet.size() << " bytes\n";


    // We change the first ciphertext byte.
    // First 12 bytes are the nonce.
    int index = 12;

    unsigned char original = packet[index];

    // Flip one bit
    packet[index] ^= 0x01;

    unsigned char changed = packet[index];


    // Show what we changed
    std::cout << "\nTampering:\n";
    std::cout << "Byte index: " << index << "\n";
    std::cout << "Original byte: "
              << (int)original << "\n";
    std::cout << "Changed byte: "
              << (int)changed << "\n";
    std::cout << "One bit was flipped.\n";


    // Try to decrypt
    std::string recovered;

    bool success =
        aesgcm::decrypt(key, packet, recovered);


    // Final result
    std::cout << "\nDecryption:\n";

    if (success)
    {
        std::cout << "FAIL - tampered message was accepted.\n";
        std::cout << "Recovered message: "
                  << recovered << "\n";
    }
    else
    {
        std::cout << "PASS - tampered message was rejected.\n";
        std::cout << "AES-GCM detected the modification.\n";
    }

    return 0;
}

