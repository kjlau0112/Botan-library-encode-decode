#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include "crypto.h"

crypto::crypto()
{


}

void crypto::encrypt(const std::string & plaintext)
{
    enc->set_key(key);
    //generate fresh nonce (IV)
    iv = rng.random_vec(enc->default_nonce_length());
    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> text2Encrypt(plaintext.data(), plaintext.data()+plaintext.length());
    this->pt = text2Encrypt;
    enc->start(iv);
    enc->finish(pt);
    std::cout << "enc->name() "<< enc->name()<<std::endl;
    std::cout << "Botan::hex_encode(iv) "<< Botan::hex_encode(iv) <<std::endl;
    std::cout << "Botan::hex_encode(pt) "<< Botan::hex_encode(pt) <<std::endl;
}

void crypto::decrypt()
{
    dec->set_key(key);
    dec->start(iv);
    dec->finish(pt);
    std::cout <<pt.data()<<std::endl;

}

crypto::~crypto()
{


}

int main()
{
    const std::string plaintext("LMAOplsPP5523224");
    crypto obj;
    obj.encrypt(plaintext);
    obj.decrypt();
    return 0;
}