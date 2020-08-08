#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>

class crypto
{
    public:
        void encrypt(const std::string & plaintext);
        void decrypt();
        crypto();
        ~crypto();
    
        std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);
        std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION);
        const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
        const std::vector<uint8_t> decryptkey = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());
        Botan::secure_vector<uint8_t> pt;
};