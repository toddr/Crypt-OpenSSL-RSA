#include <openssl/ssl.h>
#include "rsaLib.h"

/**
 * rsaLib.c - By Ian Robertson
 *
 * This is a collection of routines to ease the task of interfacing
 * with the openSSL libs.
 **/

static char* error;

/**
 * Take an rsa key and convert it to an ASN1-encoded string suitable
 * for storing in a file.
 *
 * Args:
 *
 *  privateFlag: true if this is a private key
 *
 *  key: The key
 *
 * Returns the string, or null on an error (and error is set).
 **/

char *makeKeyString(char privateFlag, RSA *key)
{
    BUF_MEM *bptr;
    char *ret;
    BIO *stringBIO = BIO_new(BIO_s_mem());
    if (stringBIO==NULL)
    {
        error = "Failed to create memory BIO";
        return NULL;
    }
    
    if (privateFlag)
      PEM_write_bio_RSAPrivateKey(stringBIO, key, NULL, NULL, 0, NULL, NULL);
    else
      PEM_write_bio_RSAPublicKey(stringBIO, key);
    
    BIO_flush(stringBIO);
    BIO_get_mem_ptr(stringBIO, &bptr);
    BIO_set_close(stringBIO, BIO_NOCLOSE); /* So BIO_free() leaves
                                              BUF_MEM alone */
    ret = malloc(bptr->length + 1);
    memcpy(ret, bptr->data, bptr->length + 1);
    BIO_free(stringBIO);

    return ret;
}

/**
 * Take string containing an ASN1 encoding of an RSA key and convert
 * it to an RSA structure.
 *
 * Args:
 *
 *  privateFlag: true if this is a private key
 *
 *  encoding: the string containing the encoding
 *
 * Returns the key, or null on an error.
 **/


RSA* loadKey(char privateFlag, char *encoding)
{
    RSA *key;
    BUF_MEM *encodingBuffer;
    BIO *stringBIO = BIO_new(BIO_s_mem());
    if (stringBIO==NULL)
    {
        error = "Failed to create memory BIO";
        return NULL;
    }
    
    encodingBuffer = BUF_MEM_new();
    BUF_MEM_grow(encodingBuffer, strlen(encoding) + 1);
    memcpy(encodingBuffer->data, encoding, strlen(encoding) + 1);
    BIO_set_mem_buf(stringBIO, encodingBuffer, BIO_CLOSE);

    if(privateFlag)
        key = PEM_read_bio_RSAPrivateKey(stringBIO, NULL, NULL, NULL);
    else
        key = PEM_read_bio_RSAPublicKey(stringBIO,NULL, NULL, NULL);

    BIO_free(stringBIO);
    
    if (key == NULL)
      error = "Failed to read key";

    return key;
}

void print_error()
{
  printf("Error: %s\n", error);
}

/**
 * A debugging main routine - remove before production
 **/


int main(int argc, char* argv[])
{
    RSA *rsa, *rsa_pub, *rsa_priv;

    int orig_length, enc_length, dec_length;
    int i, j;
  
    unsigned char original_message[] = "This is the original message.\n";
    unsigned char encrypted_message[255];
    unsigned char decrypted_message[255];
    char error[120];
    char *privateString;
    char *publicString;
    
    BIO *bio_out;

    int pad = RSA_PKCS1_OAEP_PADDING;
    // int pad = RSA_NO_PADDING;

    SSLeay_add_ssl_algorithms();

    SSL_load_error_strings();

    rsa = RSA_generate_key(1024, 65535, NULL, NULL);

    printf("public modulus: %s\n", BN_bn2dec(rsa->n));
    printf("public exponent: %s\n", BN_bn2dec(rsa->e));
    printf("private exponent: %s\n", BN_bn2dec(rsa->d));
    printf("p: %s\n", BN_bn2dec(rsa->p));
    printf("q: %s\n", BN_bn2dec(rsa->q));

    printf ("size: %d\n", RSA_size(rsa));

    publicString = makeKeyString(0, rsa);
    privateString = makeKeyString(1, rsa);

    printf("%s", publicString);
    printf("%s", privateString);

    rsa_pub = loadKey(0, publicString);
    rsa_priv = loadKey(1, privateString);
    /*  RSA_print_fp(stdout, rsa, 0); */
    
    orig_length = strlen(original_message)+1;

    
    for (i= 0; i< 1; i++)
    {
      enc_length = RSA_public_encrypt(orig_length, original_message,
                                        encrypted_message, rsa_pub, pad);

        printf("Enclength: %d\n", enc_length);
        
        for (j = 0; j < enc_length; j++)
        {
            printf("%02x ", encrypted_message[j]);
        }
        printf("\n\n");

        //        bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        PEM_write(stdout, "foo", "bar", encrypted_message, enc_length);

        // int     PEM_write(FILE *fp,char *name,char *hdr,unsigned char *data,long len);

    }
    
    ERR_print_errors_fp(stdout);

    dec_length = RSA_private_decrypt(enc_length, encrypted_message,
                                     decrypted_message, rsa_priv, pad);
    
    
    
    printf("Declength: %d\n", dec_length);
    
    
    printf("%s", decrypted_message);
    return 0;
}

