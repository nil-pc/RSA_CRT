#include <stdio.h>
//#include "rsa.h"
#include <cstring>
#include <time.h>
#include <mpir.h>
#include <mpirxx.h>

using namespace std;

#define PRIME_LENGTH 512
#define RSA_LENGTH 1024

mpz_t message, plaintext, ciphertext, phi_n, p, q, m;
mpz_t c1, c2;

static unsigned long seed = 311;   //Any positive integer would be OK.

typedef struct
{
	mpz_t e;
	mpz_t n;
}PublicKey;

typedef struct
{
	mpz_t d;
}PrivateKey;

void InitRandomState(gmp_randstate_t state)
{
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, seed);
}

void GeneratePrimes(mpz_t prime, gmp_randstate_t state)
{
	mpz_rrandomb(prime, state, PRIME_LENGTH);

	while (!(mpz_millerrabin(prime, 512)))
	{
		gmp_randclear(state);
		seed++;
		InitRandomState(state);
		mpz_rrandomb(prime, state, PRIME_LENGTH);
	}
	gmp_randclear(state);
	seed++;
}

void GenerateN(gmp_randstate_t state,mpz_t n, mpz_t p, mpz_t q)
{
	mpz_t M1, M2;
	mpz_inits(M1, M2, NULL);
	mpz_inits(p,q,NULL);
	InitRandomState(state);
	GeneratePrimes(p, state);
	gmp_printf("p-value:%Zd\n\n", p);
	InitRandomState(state);
	GeneratePrimes(q, state);
	gmp_printf("q-value:%Zd\n\n", q);
	mpz_mul(n, p, q);
	mpz_invert(M1, q, p);
	mpz_invert(M2, p, q);
	mpz_inits(c1, c2, NULL);
	mpz_mul(c1, q, M1);
	mpz_mul(c2, p, M2);
}

void GeneratePhi_N(mpz_t phi_n,mpz_t p, mpz_t q)
{
	mpz_t p_minus1, q_minus1;
	mpz_inits(p_minus1, q_minus1,phi_n, NULL);
	mpz_sub_ui(p_minus1, p, 1);
	mpz_sub_ui(q_minus1, q, 1);
	mpz_mul(phi_n, p_minus1, q_minus1);
	gmp_printf("phi_n-value:%Zd\n\n", phi_n);

	mpz_clears(p_minus1, q_minus1,NULL);
}
void GeneratePublicKey(PublicKey* pubkey, gmp_randstate_t state, unsigned int seed, mpz_t p, mpz_t q)
{
	mpz_set_ui(pubkey->e, 65537);
	GenerateN(state, pubkey->n, p, q);
	gmp_printf("n-value:%Zd\n\n", pubkey->n);
}

void GeneratePrivateKey(PrivateKey*privkey, mpz_t phi_n, mpz_t e)
{
	mpz_invert(privkey->d,e,phi_n);
	gmp_printf("PrivateKey:%Zd\n\n", privkey->d);
}

void RSA_Decode(mpz_t decode,  unsigned char decode_array[])
{
	mpz_import(decode, 128, 1, sizeof(decode_array[0]), 0, 0, decode_array);
}

void RSA_Encryption(mpz_t ciphertext, mpz_t plaintext,PublicKey* pubkey)
{
	mpz_powm(ciphertext, plaintext, pubkey->e, pubkey->n);		
}

void RSA_Encode(mpz_t encode, unsigned char encode_array[])
{
	mpz_export(encode_array, NULL, 1, sizeof(encode_array[0]), 0, 0, encode);
}

void RSA_Decryption(mpz_t message,  mpz_t ciphertext, PrivateKey* privkey, PublicKey* pubkey)
{
	mpz_powm(message, ciphertext, privkey->d,pubkey->n);
}

void RSA_Decryption_CRT(mpz_t m,  mpz_t ciphertext, PrivateKey* privkey, PublicKey* pubkey)
{
	mpz_t vp, vq, m1, m2;
	mpz_inits(vp, vq, m1, m2, NULL);
	mpz_powm(vp, ciphertext, privkey->d, p);
	mpz_powm(vq, ciphertext, privkey->d, q);
	mpz_mul(m1, vp, c1);
	mpz_mul(m2, vq, c2);
    mpz_add(m1, m1, m2);
    mpz_mod(m, m1, pubkey->n);
}

void KeyGeneration(PrivateKey*privKey, PublicKey* pubKey)
{		
	gmp_randstate_t state;
	GeneratePublicKey(pubKey,state,seed,p,q);
	GeneratePhi_N(phi_n, p, q);
	GeneratePrivateKey(privKey,phi_n, pubKey->e);

}

int main()
{
	
	PrivateKey privKey; PublicKey pubKey;
	mpz_inits(pubKey.e, pubKey.n, privKey.d, NULL);
	mpz_inits(plaintext, ciphertext, message, m, NULL);
	string test = "4getgt0fs947lWgfPha15Cs61r6xyjiFP6Gg4WFO3w9H0v15crwdp7dW9Tqu2L4IrCm6b8xjOLXLe1UO2Pv9j2jmi5634g20b0uZT0K6X6zSLAd3p2GCAa5j6VbUqPQq";

	
	unsigned char data_array[128] = { 0 };
	unsigned char message_array[128] = { 0 };
	copy(test.begin(), test.end(), data_array);

	KeyGeneration(&privKey,&pubKey);
	RSA_Decode(plaintext,data_array);
	gmp_printf("Plaintext Value :%Zd\n\n", plaintext);
	RSA_Encryption(ciphertext,plaintext,&pubKey);

    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);

	RSA_Decryption(message,ciphertext,&privKey,&pubKey);
	RSA_Encode(message, message_array);

	gmp_printf("Message Value:%Zd\n", message);

    clock_gettime(CLOCK_MONOTONIC, &tend);
    printf("\nKey Generation & Encryption-Decryption took %.8f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec)); 

    tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);

	RSA_Decryption_CRT(m,ciphertext,&privKey,&pubKey);
	RSA_Encode(m, message_array);

	gmp_printf("Message Value:%Zd\n", m);

    clock_gettime(CLOCK_MONOTONIC, &tend);
    printf("\nKey Generation & Encryption-Decryption took %.8f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));     

	return 0;

}
