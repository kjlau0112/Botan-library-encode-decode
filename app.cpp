#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
int main()
{
    Botan::AutoSeeded_RNG rng;
    const std::string plaintext("Pa$$5523224lkj");
    const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
    const std::vector<uint8_t> decryptkey = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);
    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION);
    
    enc->set_key(key);
    //generate fresh nonce (IV)
    Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());
    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());
    enc->start(iv);
    enc->finish(pt);
    std::cout << "enc->name() "<< enc->name()<<std::endl;
    std::cout << "Botan::hex_encode(iv) "<< Botan::hex_encode(iv) <<std::endl;
    std::cout << "Botan::hex_encode(pt) "<< Botan::hex_encode(pt) <<std::endl;

    dec->set_key(decryptkey);
    dec->start(iv);
    dec->finish(pt);
    std::cout <<pt.data()<<std::endl;

    return 0;
}

//const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");