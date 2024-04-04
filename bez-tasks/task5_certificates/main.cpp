#include <iostream>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <memory>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>

#define bufsize 1024

using namespace std;

bool checkOpenFile(ofstream &stream){
    if(stream.is_open()){
        return true;
    }
    else{
        cout << "Error: Could not open file" << std::endl;
        return false;
    }
}


bool checkFileBad(ofstream &stream){
    if(stream.fail()){
        cout << "Error: File is corrupted" << std::endl;
        return true;
    }
    else{
        return false;
    }
}


int main() {
    std::cout << "Hello, World!" << std::endl;

    //socket
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        std::cout << "Error creating socket" << std::endl;
        return 1;
    }


    sockaddr_in sAddress{};
    memset(&sAddress, 0, sizeof(sAddress));
    sAddress.sin_family = AF_INET;
    sAddress.sin_port = htons(443);
    sAddress.sin_addr.s_addr = inet_addr("147.32.232.212");

    if (connect(sockFd, (sockaddr *) & sAddress, sizeof(sAddress)) < 0) {
        std::cout << "Error connecting to server" << std::endl;
        return 1;
    }






    //ssl create
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        std::cout << "Error creating context" << std::endl;
        return 1;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL *ssl = SSL_new(ctx);
    if (ssl == nullptr) {
        std::cout << "Error creating SSL" << std::endl;
        SSL_CTX_free(ctx);
        return 1;
    }

    if(! SSL_set_fd(ssl, sockFd) ) {
        std::cout << "Error setting socket" << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    //default used is "TLS_AES_256_GCM_SHA384"
    //TLS -> Transport Layer Security, protocol being used
    //AES_256 -> Advanced Encryption Standard with 256-bit keys, symmetric cipher
    //GCM ->  Galois/Counter mode, high performance mode for AES using parallel processing
    //SHA384 -> Secure hash algorithm, hash function with 384-bit hash output
    
    //TLS_CHACHA20_POLY1305_SHA256 used instead
    if( !SSL_set_ciphersuites(ssl,
                         "TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256:TLS_CHACHA20_POLY1305_SHA256") ) {
        std::cout << "Error setting cipher suites" << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }





    //ssl connect
    if(! SSL_connect(ssl) ) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        std::cout << "Error connecting SSL" << std::endl;
        return 1;
    }

    auto cipher = SSL_get_cipher_name(ssl);
    cout << "Cipher: " << cipher << endl;






    //certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert == nullptr) {
        std::cout << "Error getting certificate" << std::endl;
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        return 1;
    }

    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    cout << "Subject: " << subj << endl;
    cout << "Issuer: " << issuer << endl;
    free(subj);
    free(issuer);


    if( access( "cert.pem", F_OK ) == 0  ) {
        // file exists
        if(remove("cert.pem")  == -1) {
            std::cout << "Error removing file" << std::endl;
            SSL_shutdown(ssl);
            close(sockFd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            X509_free(cert);
            return 1;
        }
    } else {
        // file doesn't exist
        cout << "old cert.pem cannot be removed because it doesn't exist" << std::endl;
    }


    FILE* fp = fopen("cert.pem", "w");
    if(fp == nullptr) {
        std::cout << "Error opening file" << std::endl;
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        return 1;
    }


    if(! PEM_write_X509(fp, cert) ) {
        std::cout << "Error writing certificate" << std::endl;
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        fclose(fp);
        return 1;
    }

    if( fclose(fp) == EOF) {
        std::cout << "Error closing file" << std::endl;
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        return 1;
    }




    //ssl verify
    if(! SSL_CTX_load_verify_locations(ctx, "cert.pem", nullptr) ) {
        std::cout << "Error loading certificate" << std::endl;
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        return 1;
    }

    if( SSL_get_verify_result(ssl)  == X509_V_OK ) {
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        std::cout << "Error verifying SSL" << std::endl;
        return 1;
    }
    else {
        std::cout << "SSL successfully verified" << std::endl;
    }





    //ssl write
    char buffer[bufsize];
    const char* httpGet = "GET /cs/fakulta/o-fakulte HTTP/1.0\r\nHost: fit.cvut.cz\r\n\r\n";

    if(SSL_write(ssl, httpGet, (int)strlen(httpGet)) <= 0) {
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        std::cout << "Error SSL write" << std::endl;
        return 1;
    }






    //ssl read
    int bytes;
    ofstream file("output.html", ios::out|ios::binary);
    if( checkFileBad(file) || !checkOpenFile(file) ) {
        std::cout << "Error Bad ofstream" << std::endl;
        SSL_shutdown(ssl);
        close(sockFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        remove("output.html");
        file.close();
        return 1;
    }
    while( (bytes = SSL_read(ssl, buffer, bufsize) ) ) {
        if(bytes <= 0) {
            std::cout << "Error SSL read" << std::endl;
            SSL_shutdown(ssl);
            close(sockFd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            X509_free(cert);
            remove("output.html");
            file.close();
            return 1;
        }


        if( ! file.write(buffer, bytes) || checkFileBad(file) ) {
            std::cout << "Error writing to file" << std::endl;
            SSL_shutdown(ssl);
            close(sockFd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            X509_free(cert);
            remove("output.html");
            file.close();
            return 1;
        }
    }
    file.close();






    //finish
    SSL_shutdown(ssl);
    close(sockFd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    X509_free(cert);


    cout << "Done" << endl;

    return 0;
}
