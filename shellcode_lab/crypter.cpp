#include <iostream>
#include <iomanip>
#include <sstream>

#include <algorithm>
#include <random>

#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>

typedef std::vector<unsigned char> bytearr_t;

bytearr_t generate_key(size_t len)
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_real_distribution<double> dist(0, 256);

    bytearr_t ret;

    for (auto i = 0; i < len; ++i)
        ret.push_back((unsigned char)dist(mt));

    return ret;
}

bytearr_t one_time_xor(bytearr_t sc, bytearr_t key)
{
    bytearr_t ret;

    assert(sc.size() == key.size());

    for (auto i = 0; i < sc.size(); ++i)
        ret.push_back(sc[i] ^ key[i]);

    return ret;
}

void print_bytearr(bytearr_t bytes)
{
    for (auto const &byte : bytes)
        std::cout << "\\x" << std::setw(2) << std::setbase(16) << std::setfill('0') << (int)byte;
        
    std::cout << std::endl;
}

bytearr_t str_to_bytearr(std::string str)
{
    str.erase(std::remove(str.begin(), str.end(), '\\'), str.end());
    std::replace(str.begin(), str.end(), 'x', ' ');
    str.erase(0, 1);

    bytearr_t bytes;
    int num = 0;

    for (size_t i = 0; i < (str.size() + 1) / 3; ++i)
    {
        std::string numStr = str.substr(i * 3, str.find(" "));
        sscanf(numStr.c_str(), "%x", &num); // isolated overflow
        bytes.push_back((unsigned char) num);
    }

    return bytes;
}

void show_usage()
{
    std::cout << "Encrypt: scrypter [shellcode]" << std::endl;
    std::cout << "Decrypt: scrypter -d [key] [shellcode]" << std::endl;
}

int encrypt(int argc, char *argv[])
{
    if (argc != 2)
        return -1;

    auto bytes = str_to_bytearr(argv[1]);
    auto key = generate_key(bytes.size());
    auto encrypted = one_time_xor(bytes, key);

    std::cout << "Size: " << bytes.size() << std::endl;
    std::cout << std::endl << "Key: " << std::endl;
    print_bytearr(key);
    std::cout << std::endl << "Encrypted: " << std::endl;
    print_bytearr(encrypted);

    return 0;
}

int decrypt(int argc, char *argv[])
{
    if (argc != 4)
        return -1;

    auto key = str_to_bytearr(argv[2]);
    auto encrypted = str_to_bytearr(argv[3]);
    auto decrypted =  one_time_xor(encrypted, key);

    print_bytearr(decrypted);

    std::cout << std::endl << "Press any key to execute...";
    getchar();

    char *shellcode = reinterpret_cast<char*> (&decrypted[0]);
    (*(void(*)()) shellcode)();
}

int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp(argv[1], "-d") == 0)
        return decrypt(argc, argv);

    return encrypt(argc, argv);
}
