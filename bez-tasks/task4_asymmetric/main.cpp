//Andrej Ohrablo

#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>



#define AES_CIPHER 45678

#define ECB 123456
#define CBC 654321

#define BUF_SIZE 1024

#define AES_KEYLEN 32
#define AES_IVLEN 16

using namespace std;
bool checkopenFile(fstream &stream){
    if(stream.is_open()){
        return true;
    }
    else{
        cout << "Error: Could not open file" << std::endl;
        return false;
    }
}


bool checkFileBad(fstream &stream){
    if(stream.fail()){
        cout << "Error: File is corrupted" << std::endl;
        return true;
    }
    else{
        return false;
    }
}


//encrypt inputFile with openssl EVP_EncryptInit_ex
bool encrypt(fstream &inputFile, fstream &outputFile,  EVP_PKEY * pubkey){
    int len;
    int plaintext_len;
    unsigned char plaintext[BUF_SIZE];
    unsigned char ciphertext[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char iv[AES_IVLEN] = "";

    if (RAND_load_file("/dev/urandom", 1024) != 1024) {
        cout << "Cannot seed the random generator!" << endl;
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        cout << "Error: EVP_CIPHER_CTX_new failed" << std::endl;
        return false;
    }

    inputFile.seekg(0, ios::beg);


    if(inputFile.eof()){
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    auto * my_ek = new unsigned char[EVP_PKEY_size(pubkey)]; // allocate space for encrypted symmet. key
    int my_ekl; // enc. sym. key length

    int cipher = AES_CIPHER;
    int mode = ECB;

    if(cipher == AES_CIPHER){
        if(mode ==  ECB){
            if(!EVP_SealInit(ctx, EVP_aes_256_ecb(), &my_ek, &my_ekl, iv, &pubkey, 1)){
                cout << "Error: EVP_SealInit failed" << endl;
                EVP_CIPHER_CTX_free(ctx);
                delete[] my_ek;
                return false;
            };
        }
        else if(mode == CBC){
            if(!EVP_SealInit(ctx, EVP_aes_256_cbc(), &my_ek, &my_ekl, iv, &pubkey, 1)){
                cout << "Error: EVP_SealInit failed" << endl;
                EVP_CIPHER_CTX_free(ctx);
                delete[] my_ek;
                return false;
            };
        }
        else{
            cout << "Error: Invalid mode" << endl;
            EVP_CIPHER_CTX_free(ctx);
            delete[] my_ek;
            return false;
        }
    }
    else{
        cout << "Error: Invalid cipher" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }

    //write cipher to output file
    if( ! outputFile.write(reinterpret_cast<const char *>(&cipher),sizeof(cipher)) || checkFileBad(outputFile) ){
        cout << "Error: Could not write cipher to file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }

    //write mode to output file
    if( ! outputFile.write(reinterpret_cast<const char *>(&mode), sizeof(mode)) || checkFileBad(outputFile) ){
        cout << "Error: Could not write mode to file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }
    //write encrypted symmetric key length to output file
    if( ! outputFile.write(reinterpret_cast<const char *>(&my_ekl), sizeof(my_ekl)) || checkFileBad(outputFile)){
        cout << "Error: Could not write encrypted symmetric key to file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }

    //write encrypted symmetric key to output file
    if( ! outputFile.write((char*)my_ek, my_ekl) || checkFileBad(outputFile)){
        cout << "Error: Could not write encrypted symmetric key to file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }

    //write iv to output file
    if( ! outputFile.write((char*)iv, AES_IVLEN) || checkFileBad(outputFile)){
        cout << "Error: Could not write iv to file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }



    while(!inputFile.eof()){
        //reads from stream
        inputFile.read((char*)plaintext, BUF_SIZE/sizeof(char));
        //checks amount of characters read and works with that amount
        plaintext_len = (int)inputFile.gcount();
        if(plaintext_len == 0){
            break;
        }
        if(!EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
            cout << "Error: EVP_SealUpdate failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            delete[] my_ek;
            return false;
        }
        if(! outputFile.write((char*)ciphertext, len) || checkFileBad(outputFile))
        {
            cout << "Error: Could not write ciphertext to file" << endl;
            EVP_CIPHER_CTX_free(ctx);
            delete[] my_ek;
            return false;
        }
        //checks if the next character is not eof, if it is not, there is some data leftover and one more loop is needed
        int e = inputFile.peek();
        if(e == EOF){
            break;
        }
    }


    if(!EVP_SealFinal(ctx, ciphertext, &len)){
        cout << "Error: EVP_SealFinal failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }


    if(! outputFile.write((char*)ciphertext, len) || checkFileBad(outputFile))
    {
        cout << "Error: Could not write ciphertext to file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    delete[] my_ek;
    return true;
}

//read evp pkey from file
EVP_PKEY* getPublickey(const char * inputFile){
    EVP_PKEY * pubkey;
    FILE * fileOfPublicKey = fopen(inputFile,"r");
    //check if fileOfPublicKey is ferror
    if(ferror(fileOfPublicKey)){
        cout << "Error: Could not open file" << endl;
        return nullptr;
    }
    pubkey = PEM_read_PUBKEY(fileOfPublicKey, NULL, NULL, NULL);
    fclose(fileOfPublicKey);
    return pubkey;
}


//read evp pem private key from file
EVP_PKEY* getPrivatekey(const char * inputFile){
    EVP_PKEY * privkey;
    FILE * fileOfPrivateKey = fopen(inputFile,"r");
    if(ferror(fileOfPrivateKey)){
        cout << "Error: Could not open file" << endl;
        return nullptr;
    }
    privkey = PEM_read_PrivateKey(fileOfPrivateKey, NULL, NULL, NULL);
    fclose(fileOfPrivateKey);
    return privkey;
}

//call encrypt with two files and close them if encrypt is not successful
bool encryptFile(const string& inputname, const string& outputname, const char * publickeyFile){

    const string& publickeyFileName = publickeyFile;
    fstream publickeyStream;
    publickeyStream.open(publickeyFileName, ios::in | ios::binary);

    if(!checkopenFile(publickeyStream)){
        cout << "Error: Could not open public key file" << endl;
        return false;
    }

    EVP_PKEY * pubkey = getPublickey(publickeyFile);
    if(pubkey == nullptr){
        cout << "Error: Could not read public key" << endl;
        EVP_PKEY_free(pubkey);
        return false;
    }

    const string& inputFileName = inputname;
    fstream inputFile;
    inputFile.open(inputFileName, ios::in | ios::binary);

    if(!checkopenFile(inputFile)){
        cout << "Error: Could not open input file" << endl;
        EVP_PKEY_free(pubkey);
        return false;
    }

    const string& outputFileName = outputname;
    fstream outputFile;
    outputFile.open(outputFileName, ios::out | ios::binary);
    if(!checkopenFile(outputFile)){
        cout << "Error: Could not open output file" << endl;
        EVP_PKEY_free(pubkey);
        return false;
    }
    if(!encrypt(inputFile, outputFile, pubkey)){
        cout << "Error: Encryption failed" << endl;
        inputFile.close();
        outputFile.close();
        cout << "Deleting output file" << endl;
        remove(outputFileName.c_str());
        EVP_PKEY_free(pubkey);
        return false;
    }
    cout << "Encryption successful" << endl;
    inputFile.close();
    outputFile.close();
    EVP_PKEY_free(pubkey);
    return true;
}



//decrypt inputFile with openssl EVP_DecryptInit_ex
bool decrypt(fstream &inputFile, fstream &outputFile, EVP_PKEY * privkey){
    int len;
    int ciphertext_len;
    unsigned char ciphertext[BUF_SIZE];
    unsigned char plaintext[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];


    inputFile.seekg(0, std::fstream::end);
    int inputFileSize = inputFile.tellg();
    inputFile.seekg(0, std::fstream::beg);


    int cipher;
    if( ! inputFile.read((char*)&cipher, sizeof(int)) || checkFileBad(inputFile)){
        cout << "Error: Could not read cipher" << endl;
        return false;
    }
    int mode;
    if(! inputFile.read((char*)&mode, sizeof(int)) || checkFileBad(inputFile)){
        cout << "Error: Could not read mode" << endl;
        return false;
    }
    int my_ekl;
    if( ! inputFile.read((char*)&my_ekl, sizeof(int)) || checkFileBad(inputFile)){
        cout << "Error: Could not read ekl" << endl;
        return false;
    }
    if(my_ekl > EVP_PKEY_size(privkey) || my_ekl <= 0 || my_ekl > (inputFileSize - (int)(3*sizeof(int)))){
        cout << "Error: Encrypted key length is too long" << endl;
        return false;
    }
    auto * my_ek = new unsigned char[my_ekl]; // allocate space for encrypted symmet. key
    if( ! inputFile.read((char*)my_ek, my_ekl) || checkFileBad(inputFile)) {
        cout << "Error: Could not read ek" << endl;
        delete[] my_ek;
        return false;
    }
    unsigned char iv[AES_IVLEN];
    if( ! inputFile.read((char*)iv, AES_IVLEN) || checkFileBad(inputFile) ){
        cout << "Error: Could not read iv" << endl;
        delete[] my_ek;
        return false;
    }


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        cout << "Error: Could not create cipher context" << endl;
        delete[] my_ek;
        return false;
    }



    if(inputFile.eof()){
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return true;
    }

    if(cipher == AES_CIPHER){
        if(mode ==  ECB){
            if(!EVP_OpenInit(ctx, EVP_aes_256_ecb(), my_ek, my_ekl, iv, privkey)){
                cout << "Error: EVP_OpenInit failed" << endl;
                EVP_CIPHER_CTX_free(ctx);
                delete[] my_ek;
                return false;
            };
        }
        else if(mode ==  CBC){
            if(!EVP_OpenInit(ctx, EVP_aes_256_cbc(), my_ek, my_ekl, iv, privkey)){
                cout << "Error: EVP_OpenInit failed" << endl;
                EVP_CIPHER_CTX_free(ctx);
                delete[] my_ek;
                return false;
            };
        }
        else{
            cout << "Error: Invalid mode" << endl;
            EVP_CIPHER_CTX_free(ctx);
            delete[] my_ek;
            return false;
        }
    }
    else{
        cout << "Error: Invalid cipher" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }



    while(!inputFile.eof()){
        //reads from stream
        inputFile.read((char*)ciphertext, BUF_SIZE/sizeof(char));
        //checks amount of characters read and works with that amount
        ciphertext_len = (int)inputFile.gcount();
        if(ciphertext_len == 0){
            break;
        }
        if(!EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
            cout << "Error: EVP_OpenUpdate failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            delete[] my_ek;
            return false;
        }
        if(! outputFile.write((char*)plaintext, len) || checkFileBad(outputFile)) {
            cout << "Error: Could not write to output file" << endl;
            EVP_CIPHER_CTX_free(ctx);
            delete[] my_ek;
            return false;
        };
        //checks if the next character is not eof, if it is not, there is some data leftover and one more loop is needed
        int e = inputFile.peek();
        if(e == EOF){
            break;
        }
    }


    if(!EVP_OpenFinal(ctx, plaintext, &len)){
        cout << "Error: EVP_OpenFinal failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    }

    if(! outputFile.write((char*)plaintext, len) || checkFileBad(outputFile)) {
        cout << "Error: Could not write to output file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] my_ek;
        return false;
    };
    EVP_CIPHER_CTX_free(ctx);
    delete[] my_ek;
    return true;
}

//call decrypt with two files and close them if encrypt is not successful
bool decryptFile(const string& inputname, const string& outputname, const char * privatekeyFile){


    const string& privatekeyFileName = privatekeyFile;
    fstream privatekeyStream;
    privatekeyStream.open(privatekeyFileName, ios::in | ios::binary);

    if(!checkopenFile(privatekeyStream)){
        cout << "Error: Could not open public key file" << endl;
        return false;
    }

    EVP_PKEY * privkey = getPrivatekey(privatekeyFile);
    if(privkey == nullptr){
        cout << "Error: Could not read public key" << endl;
        EVP_PKEY_free(privkey);
        return false;
    }

    const string& inputFileName = inputname;
    fstream inputFile;
    inputFile.open(inputFileName, ios::in | ios::binary);

    if(!checkopenFile(inputFile)){
        cout << "Error: Could not open input file" << endl;
        EVP_PKEY_free(privkey);
        return false;
    }

    const string& outputFileName = outputname;
    fstream outputFile;
    outputFile.open(outputFileName, ios::out | ios::binary);
    if(!checkopenFile(outputFile)){
        cout << "Error: Could not open output file" << endl;
        EVP_PKEY_free(privkey);
        return false;
    }
    if(!decrypt(inputFile, outputFile, privkey)){
        cout << "Error: Decryption failed" << endl;
        inputFile.close();
        cout << "Deleting output file" << endl;
        remove(outputFileName.c_str());
        outputFile.close();
        EVP_PKEY_free(privkey);
        return false;
    }
    cout << "Decryption successful" << endl;
    inputFile.close();
    outputFile.close();
    EVP_PKEY_free(privkey);
    return true;
}


int main(int argc, char **argv) {
    std::cout << "Hello, World!" << std::endl;

    if (RAND_load_file("/dev/urandom", 1024) != 1024) {
        cout << "Cannot seed the random generator!" << endl;
        return -1;
    }

    //check number of arguments
    if(argc == 5){
        cout << "Number of arguments is correct" << endl;
    }
    else if(argc == 1){
        cout << "Program Usage: " << endl;

        cout << "arg1: -e or -d to encrypt or decrypt" << endl;
        cout << "arg2: name of file with public/private key" << endl;
        cout << "arg3: input file to be encrypted or decrypted" << endl;
        cout << "arg4: output file where output will be written" << endl;
        cout << "Example1: ./main -e public.pem input.txt encrypted.txt" << endl;
        cout << "Example2: ./main -d privkey.pem encrypted.txt decrypted.txt" << endl;

        return 0;
    }
    else if(argc < 5){
        cout << "Error: Not enough arguments" << endl;
        return 1;
    }
    else if(argc > 5){
        cout << "Error: Too many arguments" << endl;
        return 1;
    }
    else{
        cout << "How???" << endl;
        return 666;
    }

    //check if the first argument is -e or -d
    if(strcmp(argv[1], "-e") == 0){
        cout << "Encrypting" << endl;
        if(!encryptFile(argv[3],argv[4],argv[2])){
            cout << "Error: Encryption failed" << endl;
            return 1;
        }
    }
    else if(strcmp(argv[1], "-d") == 0){
        cout << "Decrypting" << endl;
        if(!decryptFile(argv[3],argv[4],argv[2])){
            cout << "Error: Decryption failed" << endl;
            return 1;
        }
    }
    else{
        cout << "Error: Invalid argument" << endl;
        return 1;
    }

    return 0;
}

