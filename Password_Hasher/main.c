#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define MAX_LEN 256

void print_hash(unsigned char *hash, unsigned int len) {
    for (unsigned int i = 0; i < len; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

void hash_password(const char *pw, const char *algo_name) {
    const EVP_MD *algo = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[MAX_LEN];
    unsigned int hash_len = 0;

    if (!ctx) {
        printf("Error: failed to create digest context.\n");
        return;
    }

    if (strcmp(algo_name, "md5") == 0) {
        algo = EVP_md5();
    } else if (strcmp(algo_name, "sha256") == 0)
        algo = EVP_sha256();
    else if (strcmp(algo_name, "sha512") == 0)
        algo = EVP_sha512();
    else {
        printf("Unsupported algorithm: %s\n", algo_name);
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestInit_ex(ctx, algo, NULL) != 1 ||
        EVP_DigestUpdate(ctx, pw, strlen(pw)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        printf("Hashing failed.\n");

    } else {
        printf("%s: ", algo_name);
        print_hash(hash, hash_len);
    }

    EVP_MD_CTX_free(ctx);
}

int main() {
    char pw[MAX_LEN], algo[16];

    printf("Enter password: ");
    if (scanf("%255s", pw) != 1) {
        printf("Invalid password input.\n");
        return 1;
    }

    printf("Choose algorithm (md5 / sha256 / sha512): ");
    if (scanf("%15s", algo) != 1) {
        printf("Invalid algorithm input.\n");
        return 1;
    }

    hash_password(pw, algo);
    return 0;
}