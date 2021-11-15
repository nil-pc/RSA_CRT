#include <stdio.h>
#include <iostream>
#include <cstring>
#include <time.h>
#include <mpir.h>
#include <mpirxx.h>

using namespace std;

#define PRIME_LENGTH 512
#define RSA_LENGTH 1024

mpz_t message, plaintext, ciphertext, phi_n, p, q, m;
mpz_t c1, c2;

//Initialise a seed for prime number generation
static unsigned long seed = 311;

//Public Key n and e
typedef struct
{
    mpz_t e;
    mpz_t n;

} PublicKey;

//Private Key d
typedef struct
{
    mpz_t d;
} PrivateKey;

void randomStateInit(gmp_randstate_t state)
{
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
}

void generatePrimes(mpz_t prime, gmp_randstate_t state)
{
    //Generate a random number
    mpz_rrandomb(prime, state, PRIME_LENGTH);

    //Check if the number is Prime or not using Miller Rabin Test 
    while (!(mpz_millerrabin(prime, 512)))
    {
        gmp_randclear(state);
	seed++;
	randomStateInit(state);
	mpz_rrandomb(prime, state, PRIME_LENGTH);
    }
    gmp_randclear(state);
    seed++;
}

//Generate N = p * q where p and q are primes
void generateN(gmp_randstate_t state,mpz_t n, mpz_t p, mpz_t q)
{
    mpz_t M1, M2;
    mpz_inits(p, q, M1, M2, NULL);
    randomStateInit(state);

    //Generate p
    generatePrimes(p, state);
    gmp_printf("p-value:\n%Zd\n\n", p);
    randomStateInit(state);

    //Generate q
    generatePrimes(q, state);
    gmp_printf("q-value:\n%Zd\n\n", q);

    //Calculate N = p * q
    mpz_mul(n, p, q);

    //Find c1 and c2 for Chineese Remainder Theorem
    mpz_invert(M1, q, p);
    mpz_invert(M2, p, q);
    mpz_inits(c1, c2, NULL);
    mpz_mul(c1, q, M1);
    mpz_mul(c2, p, M2);
}

//Function to generate Phi(N)
void generatePhiN(mpz_t phi_n,mpz_t p, mpz_t q)
{
    mpz_t p_minus1, q_minus1;
    mpz_inits(p_minus1, q_minus1,phi_n, NULL);
    mpz_sub_ui(p_minus1, p, 1);
    mpz_sub_ui(q_minus1, q, 1);

    //phi(N) = (p -1) * (q - 1)
    mpz_mul(phi_n, p_minus1, q_minus1);
    gmp_printf("phi_n-value:\n%Zd\n\n", phi_n);

    mpz_clears(p_minus1, q_minus1,NULL);
}

//Generate value of N and e
void generatePublicKey(PublicKey* pubkey, gmp_randstate_t state, unsigned int seed, mpz_t p, mpz_t q)
{
    mpz_set_ui(pubkey->e, 65537);
    generateN(state, pubkey->n, p, q);
    gmp_printf("n-value:%Zd\n\n", pubkey->n);
}

//Generate value of d from N and e
void generatePrivateKey(PrivateKey*privkey, mpz_t phi_n, mpz_t e)
{
    mpz_invert(privkey->d,e,phi_n);
    gmp_printf("PrivateKey:%Zd\n\n", privkey->d);
}

void RSA_Decode(mpz_t decode,  unsigned char decode_array[])
{
    mpz_import(decode, 128, 1, sizeof(decode_array[0]), 0, 0, decode_array);
}

//Encryption => c = (p^e)mod n 
void RSA_Encryption(mpz_t ciphertext, mpz_t plaintext,PublicKey* pubkey)
{
    mpz_powm(ciphertext, plaintext, pubkey->e, pubkey->n);		
}

//Convert INT Array to string
void RSA_Encode(mpz_t encode, unsigned char encode_array[])
{
    mpz_export(encode_array, NULL, 1, sizeof(encode_array[0]), 0, 0, encode);
}

//Normal RSA decryption => m = (c^d)mod n
void RSA_Decryption(mpz_t message,  mpz_t ciphertext, PrivateKey* privkey, PublicKey* pubkey)
{
    mpz_powm(message, ciphertext, privkey->d,pubkey->n);
}

//Decryption using Chineese Remainder theorem
void RSA_Decryption_CRT(mpz_t m,  mpz_t ciphertext, PrivateKey* privkey, PublicKey* pubkey)
{
    mpz_t vp, vq, m1, m2;
    mpz_inits(vp, vq, m1, m2, NULL);

    // vp = (c^d)mod p
    mpz_powm(vp, ciphertext, privkey->d, p);
    
    // vq = (c^d)mod q
    mpz_powm(vq, ciphertext, privkey->d, q);
    mpz_mul(m1, vp, c1);
    mpz_mul(m2, vq, c2);
    mpz_add(m1, m1, m2);

    // m = (vp*c1 + vq*c2) mod n
    mpz_mod(m, m1, pubkey->n);
}

//Function to generate the public key and private key
void keyGeneration(PrivateKey*privKey, PublicKey* pubKey)
{		
    gmp_randstate_t state;
    generatePublicKey(pubKey,state,seed,p,q);
    generatePhiN(phi_n, p, q);
    generatePrivateKey(privKey,phi_n, pubKey->e);
}

int main()
{
	
    PrivateKey privKey; PublicKey pubKey;
    mpz_inits(pubKey.e, pubKey.n, privKey.d, NULL);
    mpz_inits(plaintext, ciphertext, message, m, NULL);
    double time_diff = 0, t1, t2;

    //Consider the following string for encryption
    string test = "4getgt0fs947lWgfPha15Cs61r6xyjiFP6Gg4WFO3w9H0v15crwdp7dW9Tqu2L4IrCm6b8xjOLXLe1UO2Pv9j2jmi5634g20b0uZT0K6X6zSLAd3p2GCAa5j6VbUqPQq";
	
    unsigned char data_array[128] = { 0 };
    unsigned char message_array[128] = { 0 };
    copy(test.begin(), test.end(), data_array);

    keyGeneration(&privKey, &pubKey);
    RSA_Decode(plaintext, data_array);
    gmp_printf("Plaintext Value :\n%Zd\n\n", plaintext);
	
    RSA_Encryption(ciphertext, plaintext, &pubKey);

    gmp_printf("Ciphertext Value:\n%Zd\n\n", ciphertext);

    //RSA Decryption without using Chineese Remainder theorem
    cout<<"Decryption without Chineese Remainder theorem\n";

    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);

    RSA_Decryption(message, ciphertext, &privKey,&pubKey);
    RSA_Encode(message, message_array);

    gmp_printf("Message Value:\n%Zd\n\n", message);

    clock_gettime(CLOCK_MONOTONIC, &tend);
    t1 = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
    cout<<"\nDecryption without Chineese Remainder theorem took "<<t1<<" seconds\n\n";

    //RSA Decryption using Chineese Remainder theorem
    cout<<"Decryption using Chineese Remainder theorem\n";

    tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);

    RSA_Decryption_CRT(m, ciphertext, &privKey, &pubKey);
    RSA_Encode(m, message_array);

    gmp_printf("Message Value:\n%Zd\n", m);

    clock_gettime(CLOCK_MONOTONIC, &tend);
    t2 = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
    cout<<"\nDecryption using Chineese Remainder theorem took "<<t2<<" seconds\n\n";

    time_diff = t1 - t2;
    cout<<"Time difference = "<<time_diff<<"\n\n";
    return 0; 
}
