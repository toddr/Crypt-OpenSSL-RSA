/**
 * rsaLib.h
 *
 * By Ian Robertson
 *
 **/

#include <openssl/ssl.h>

char* makeKeyString(char privateFlag, RSA *key);
RSA* loadKey(char private_flag, char *encoding);
void print_error();
