#include <stdio.h>
#include <openssl/bn.h>
void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
// Task 2: Encrypting a message
int main ()
{
    // Initializing all the variables we might need 
    // for private key creation
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *c = BN_new();

    // Assigning variables to their given 
    // values as specified in the lab description
    BN_hex2bn(&M, "4f5520436f6e6e6f72");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // We use formula c = m^e mod n to encrypt our messages
    BN_mod_exp(c, M, e, n, ctx);

    // Prints out all of or values for easy viewing
    printBN("E value = ", e);
    printBN("N value = ", n);
    printBN("M value = ", M);

    // Prints our ciphertext value
    printBN("Ciphertext C value = ", c);

    return 0;
}