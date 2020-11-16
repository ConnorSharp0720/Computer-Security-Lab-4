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
// Task 5: Verifying a Signature
int main ()
{
    // Initializing all the variables we might need 
    // for private key creation
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    BIGNUM *m2 = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *s2 = BN_new();

    // Assigning variables to their given 
    // values as specified in the lab description
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&s2,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");

    // We use formula m = s^e mod n to verify our message
    // we do it twice here to show the differences between 2 similar messages
    BN_mod_exp(m, s, e, n, ctx);
    BN_mod_exp(m2, s2, e, n, ctx);

    // Prints out all of or values for easy viewing
    printBN("E value = ", e);
    printBN("N value = ", n);
    printBN("M value = ", m);

    printBN("Signed value S = ", s);
    printBN("New Signed value S2 = ", s2);

    return 0;
}