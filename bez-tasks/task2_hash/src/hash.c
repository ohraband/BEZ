#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/evp.h>


int main (int argc, char * argv[]) {
    //char text[] = "Text pro hash.";

    if( argc == 2 ) {
        printf("The argument supplied is %s\n", argv[1]);
    }
    else if( argc > 2 ) {
        printf("Too many arguments supplied.\n");
        return -1;
    }
    else {
        printf("One argument expected.\n");
        return -1;
    }

    if(!isdigit(*argv[1])) {
        printf("%s is not a digit.\n", argv[1]);
        return -1;
    }

    int leadingzeroes = atoi(argv[1]);
    if(leadingzeroes > 512 || leadingzeroes < 0){
        printf("Input a number from 0 to 512.\n");
        return -1;
    }
    int loops = 10;
    int loops2 = loops;



    static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int stringlen = 800;
    char  text[stringlen + 5];
    float  avgtimes[15];
    for(int i =0 ; i < stringlen; i++){
        text[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    clock_t start = clock();
    int increment = 0;
    while(1){
        text[increment++ % stringlen] = alphanum[rand() % (sizeof(alphanum) - 1)];
        //GenerateHash(text);
        char hashFunction[] = "sha512";  // zvolena hashovaci funkce ("sha1", "md5", ...)

        EVP_MD_CTX * ctx;  // struktura kontextu
        const EVP_MD * type; // typ pouzite hashovaci funkce
        unsigned char hash[EVP_MAX_MD_SIZE]; // char pole pro hash - 64 bytu (max pro sha 512)
        unsigned int length;  // vysledna delka hashe

        /* Inicializace OpenSSL hash funkci */
        OpenSSL_add_all_digests();
        /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
        type = EVP_get_digestbyname(hashFunction);

        /* Pokud predchozi prirazeni vratilo -1, tak nebyla zadana spravne hashovaci funkce */
        if (!type) {
            printf("Hash %s neexistuje.\n", hashFunction);
            return 1;
        }

        ctx = EVP_MD_CTX_new(); // create context for hashing
        if (ctx == NULL){
            printf("Ctx drop\n");
            return 2;
        }


        /* Hash the text */
        if (!EVP_DigestInit_ex(ctx, type, NULL)){ // context setup for our hash type
            printf("EVP_DigestInit drop\n");
            return 3;}



        if (!EVP_DigestUpdate(ctx, text, strlen(text))) {// feed the message in
            printf("EVP_DigestUpdate drop\n");
            return 4;
        }

        if (!EVP_DigestFinal_ex(ctx, hash, &length)){  // get the hash
            printf("EVP_DigestFinal_ex drop\n");
            return 5;
        }

        EVP_MD_CTX_free(ctx); // destroy the context


        int nullbytes = leadingzeroes / 8;
        int lastbytezeros = leadingzeroes % 8;
        int isgood = 1;

        for(int i =0; i < nullbytes ; i++){
            if(hash[i] != 0){
                isgood = 0;
                break;
            }
        }

        if(lastbytezeros > 0 && isgood){
            int lastbyte = hash[nullbytes];
            while(lastbytezeros){
                lastbyte *= 2;
                if(lastbyte < 0xff){
                    lastbytezeros--;
                }
                else{
                    isgood = 0;
                    break;
                }
            }
        }



        if(isgood){
            /* Vypsani vysledneho hashe */
             printf("Hash textu \"%s\" je: \n", text);
             for (unsigned int i = 0; i < length; i++)
                 printf("%02x", hash[i]);
             printf("\n");
            break;

            //Measuring average time
//            clock_t end = clock();
//            float seconds = (float)(end - start) / CLOCKS_PER_SEC;
//            printf("TIME TAKEN: %f\n", seconds);
//            start = clock();
//            if(!loops--){
//                float sum = 0;
//                for(int i = 0; i < loops2; i++){
//                    sum += avgtimes[i];
//                }
//                float avg = sum/loops2;
//                printf("AVG TIME: %f\n", avg);
//                return 0;
//            }
//            else{
//                avgtimes[loops] = seconds;
//            }
        }
    }
    return 0;
}

