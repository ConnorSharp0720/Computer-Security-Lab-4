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

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *one = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *pMinus = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *qMinus = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phiN = BN_new();
    BIGNUM *d = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_dec2bn(&one, "1");

    // pMinus = p - one
    BN_sub(pMinus, p, one);
    // pMinus = q - one
    BN_sub(qMinus, q, one);

    // n = p*q
    BN_mul(n, p, q, ctx);

    // phiN = pMinus * qMinus
    BN_mul(phiN, pMinus, qMinus, ctx);

    //d = multiplicative inverse of e mod phi(n)
    BN_mod_inverse(d, e, phiN, ctx);

    printBN("P value = ", p);
    printBN("Q value = ", q);
    printBN("E value = ", e);
    printBN("N value = ", n);
    printBN("PhiN value = ", phiN);
    printBN("Pminus value = ", pMinus);
    printBN("Qminue value = ", qMinus);

    // prints out n 
    printBN("Private Key D = ", d);

    return 0;
}