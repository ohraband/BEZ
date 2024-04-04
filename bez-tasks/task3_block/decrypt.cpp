//Andrej Ohrablo

#include <iostream>
#include <cstdlib>
#include <string>
#include <fstream>
#include <openssl/evp.h>

#define ECB 1
#define CBC 2


#define AES_KEYLEN 64
#define AES_IVLEN 32

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


//copy .tga header from inputFile to outputFile
bool copyHeader(fstream &inputFile, fstream &outputFile){
    //get size of file
    inputFile.seekg(0, fstream::end);
    long int size = inputFile.tellg();
    inputFile.seekg(0, std::fstream::beg);

    if( size < 18 ){
        cout << "Error: File does not have at least 18 bytes for header." << std::endl;
        return false;
    }


    //read 1st byte of file
    int imageidlen = inputFile.get();
    //cout << "id: " <<imageidlen << std::endl;


    //read 5th byte of file
    inputFile.seekg(5, std::fstream::beg);
    int colorMapTypelo = inputFile.get();
    //cout << "colorMapTypelo: " << colorMapTypelo << std::endl;

    //read 6th byte of file
    inputFile.seekg(6, std::fstream::beg);
    int colorMapTypehi = inputFile.get();
    //cout << "colorMapTypehi: " << colorMapTypehi << std::endl;

    long int colorMapType = ( (colorMapTypehi << 8) + colorMapTypelo ) / 8;
    //cout << "colorMapType: " << colorMapType << std::endl;

    //read 7th byte of file
    inputFile.seekg(7, std::fstream::beg);
    int colorMapSize = inputFile.get();
    //cout << "colorMapSize: " << colorMapSize << std::endl;


    if(size < ( 18 + imageidlen + (colorMapType * colorMapSize) )){
        cout << "File size smaller than header: " <<  size << " Expected header: "<< (18 + imageidlen + (colorMapType * colorMapSize) ) << std::endl;
        return false;
    }
    inputFile.seekg(0, fstream::beg);
    char *header = new char[18 + imageidlen + (colorMapType * colorMapSize)];
    inputFile.read(header, ( 18 + imageidlen + (colorMapType * colorMapSize) ));
    outputFile.write(header, ( 18 + imageidlen + (colorMapType * colorMapSize) ));
    delete[] header;

    return true;
}



//decrypt inputFile with openssl EVP_DecryptInit_ex
bool decrypt(fstream &inputFile, fstream &outputFile, const int mode){
    int len;
    int ciphertext_len;
    unsigned char ciphertext[1025];
    unsigned char plaintext[2048];
    unsigned char key[AES_KEYLEN] = "unsigned char key[EVP_MAX_KEY_LENGTH]";
    unsigned char iv[AES_IVLEN] = "WAVELENGTHabcde";
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    inputFile.seekg(0, ios::beg);


    if(!copyHeader(inputFile, outputFile)){
        cout << "Error: Could not copy header" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if(inputFile.eof()){
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    if(mode ==  ECB){
        if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, iv)){
            cout << "Error: EVP_DecryptInit_ex failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        };
    }

    else if(mode == CBC){
        if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)){
            cout << "Error: EVP_DecryptInit_ex failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        };
    }
    else{
        cout << "Error: Invalid mode" << endl;
        return false;
    }


    while(!inputFile.eof()){
        //reads from stream
        inputFile.read((char*)ciphertext, 1024);
        //checks amount of characters read and works with that amount
        ciphertext_len = (int)inputFile.gcount();
        if(ciphertext_len == 0){
            break;
        }
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
            cout << "Error: EVP_DecryptUpdate failed" << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outputFile.write((char*)plaintext, len);
        //checks if the next character is not eof, if it is not, there is some data leftover and one more loop is needed
        int e = inputFile.peek();
        if(e == EOF){
            break;
        }
    }


    if(!EVP_DecryptFinal_ex(ctx, plaintext, &len)){
        cout << "Error: EVP_DecryptFinal_ex failed" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outputFile.write((char*)plaintext, len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

//call decrypt with two files and close them if encrypt is not successful
bool decryptFile(const string& name, const int mode){


    //convert argv[2] to int
    string encryptmode;
    if(mode == ECB){
        encryptmode = "ecb";
    }
    else if(mode == CBC){
        encryptmode = "cbc";
    }
    else{
        cout << "Error: Invalid mode" << endl;
        return false;
    }

    const string& inputFileName = name;
    fstream inputFile;
    inputFile.open(inputFileName, ios::in | ios::binary);

    if(inputFileName.length() < (string{".tga"}).length()){
        cout << "Error: File name too short" << endl;
        return false;
    }
    if(!checkopenFile(inputFile)){
        cout << "Error: Could not open input file" << endl;
        return false;
    }

    const string& outputFileName = inputFileName.substr(0, inputFileName.size() - 4) + "_" +  encryptmode + "_dec" + ".tga";
    fstream outputFile;
    outputFile.open(outputFileName, ios::out | ios::binary);
    if(!checkopenFile(outputFile)){
        cout << "Error: Could not open output file" << endl;
        return false;
    }
    if(!decrypt(inputFile, outputFile, mode)){
        cout << "Error: Decryption failed" << endl;
        inputFile.close();
        cout << "Deleting output file" << endl;
        remove(outputFileName.c_str());
        outputFile.close();
        return false;
    }
    cout << "Decryption successful" << endl;
    inputFile.close();
    outputFile.close();
    return true;
}


int main(int argc, char **argv) {
    std::cout << "Hello, World!" << std::endl;

    //check number of arguments
    if(argc == 3){
        cout << "Number of arguments is correct" << endl;
    }
    else if(argc < 3){
        cout << "Error: Not enough arguments" << endl;
        return 1;
    }
    else if(argc > 3){
        cout << "Error: Too many arguments" << endl;
        return 1;
    }
    else{
        cout << "How???" << endl;
        return 666;
    }

    //check if argv[2] is a valid mode
    if(argv[2][0] == '1' || argv[2][0] == '2'){
        cout << "Mode is valid" << endl;
    }
    else{
        cout << "Error: Invalid mode" << endl;
        return 1;
    }

    //convert argv[2] to int
    int mode = argv[2][0] - '0';
    string name = string{argv[1]};


    if(!decryptFile(name, mode)){
        cout << "Error: Decryption failed" << endl;
        return 1;
    }

    return 0;
}

