// Tiny bLSAG signature implementation using mjosaarinen's tiny_sha3
// and libsodium ristretto255, released to the public domain.
// - Łukasz "masflam" Drukała, 2024-05-01

#include "blsag.h"
#include "sha3.h"
#include <sodium.h>
#include <string.h>

static void hash_sha3(Hash *hash, const void *input, int input_size) {
	sha3(input, input_size, hash->bytes, sizeof(hash->bytes));
}

static void hash_to_point_ristretto(Point *P, const void *input, int input_size) {
	uint8_t hash[64];
	sha3(input, input_size, hash, sizeof(hash));
	crypto_core_ristretto255_from_hash(P->bytes, hash);
}

static void hash_to_scalar_ristretto(Scalar *a, const void *input, int input_size) {
	uint8_t hash[64];
	sha3(input, input_size, hash, sizeof(hash));
	crypto_core_ristretto255_scalar_reduce(a->bytes, hash);
}

void blsag_sign(
	const Hash *msg,
	int n,
	int pi,
	const Scalar *k_pi,
	Point *Kimg,
	const Point K[n],
	Scalar c[n],
	Scalar r[n]
) {
	// Locals (we could reuse some instead)
	Point Hp_Kpi;
	Scalar alpha;
	Point ci_Ki;
	Point ri_G;
	Point ci_Kimg;
	Point Hp_Ki;
	Point ri_Hp_Ki;
	Scalar cpi_kpi;
	uint8_t to_hash[BLSAG_ROUND_DOMAIN_SIZE + 32 + 32 + 32];
	uint8_t to_hash_point[BLSAG_KIMG_DOMAIN_SIZE + 32];
	
	// Populate constants in to_hash and to_hash_point
	memcpy(&to_hash[0], BLSAG_ROUND_DOMAIN, BLSAG_ROUND_DOMAIN_SIZE);
	memcpy(&to_hash[BLSAG_ROUND_DOMAIN_SIZE], msg->bytes, sizeof(msg->bytes));
	memcpy(&to_hash_point[0], BLSAG_KIMG_DOMAIN, BLSAG_KIMG_DOMAIN_SIZE);
	
	// Calculate the key image
	memcpy(&to_hash_point[BLSAG_KIMG_DOMAIN_SIZE], K[pi].bytes, sizeof(K[pi].bytes));
	hash_to_point_ristretto(&Hp_Kpi, to_hash_point, sizeof(to_hash_point));
	(void)! crypto_scalarmult_ristretto255(Kimg->bytes, k_pi->bytes, Hp_Kpi.bytes);
	
	// Generate the random nonce
	crypto_core_ristretto255_scalar_random(alpha.bytes);
	
	// Generate the random responses
	for (int i = 0; i < n; ++i) {
		if (i == pi) continue;
		crypto_core_ristretto255_scalar_random(r[i].bytes);
	}
	
	// Calculate challenge pi+1
	{
		crypto_scalarmult_ristretto255_base(&to_hash[BLSAG_ROUND_DOMAIN_SIZE+32], alpha.bytes);
		(void)! crypto_scalarmult_ristretto255(&to_hash[BLSAG_ROUND_DOMAIN_SIZE+32+32], alpha.bytes, Hp_Kpi.bytes);
		hash_to_scalar_ristretto(&c[(pi+1) % n], to_hash, sizeof(to_hash));
	}
	
	// Calculate the rest of the challenges
	for (int j = 1; j < n; ++j) {
		int i = (pi + j) % n;
		
		// c[i] * K[i] + r[i] * G
		(void)! crypto_scalarmult_ristretto255(ci_Ki.bytes, c[i].bytes, K[i].bytes);
		crypto_scalarmult_ristretto255_base(ri_G.bytes, r[i].bytes);
		crypto_core_ristretto255_add(&to_hash[BLSAG_ROUND_DOMAIN_SIZE+32], ci_Ki.bytes, ri_G.bytes);
		
		// c[i] * Kimg + r[i] * Hp(K[i])
		(void)! crypto_scalarmult_ristretto255(ci_Kimg.bytes, c[i].bytes, Kimg->bytes);
		memcpy(&to_hash_point[BLSAG_KIMG_DOMAIN_SIZE], K[i].bytes, sizeof(K[i].bytes));
		hash_to_point_ristretto(&Hp_Ki, to_hash_point, sizeof(to_hash_point));
		(void)! crypto_scalarmult_ristretto255(ri_Hp_Ki.bytes, r[i].bytes, Hp_Ki.bytes);
		crypto_core_ristretto255_add(&to_hash[BLSAG_ROUND_DOMAIN_SIZE+32+32], ci_Kimg.bytes, ri_Hp_Ki.bytes);
		
		hash_to_scalar_ristretto(&c[(i+1) % n], to_hash, sizeof(to_hash));
	}
	
	// Calculate r_pi
	crypto_core_ristretto255_scalar_mul(cpi_kpi.bytes, c[pi].bytes, k_pi->bytes);
	crypto_core_ristretto255_scalar_sub(r[pi].bytes, alpha.bytes, cpi_kpi.bytes);
	
	// Zeroize locals (some really don't need to be)
	sodium_memzero(Hp_Kpi.bytes, sizeof(Point));
	sodium_memzero(alpha.bytes, sizeof(Scalar));
	sodium_memzero(ci_Ki.bytes, sizeof(Point));
	sodium_memzero(ri_G.bytes, sizeof(Point));
	sodium_memzero(ci_Kimg.bytes, sizeof(Point));
	sodium_memzero(Hp_Ki.bytes, sizeof(Point));
	sodium_memzero(ri_Hp_Ki.bytes, sizeof(Point));
	sodium_memzero(cpi_kpi.bytes, sizeof(Scalar));
	sodium_memzero(to_hash, sizeof(to_hash));
	sodium_memzero(to_hash_point, sizeof(to_hash_point));
}

// Return whether the signature is valid
int blsag_verify(
	const Hash *msg,
	int n,
	const Point K[n],
	const Point *Kimg,
	const Scalar *c0,
	const Scalar r[n]
) {
	// Locals (we could reuse some instead)
	Point ci_Ki;
	Point ri_G;
	Point ci_Kimg;
	Point Hp_Ki;
	Point ri_Hp_Ki;
	Scalar cpi_kpi;
	Scalar c[2];
	uint8_t to_hash[BLSAG_ROUND_DOMAIN_SIZE + 32 + 32 + 32];
	uint8_t to_hash_point[BLSAG_KIMG_DOMAIN_SIZE + 32];
	
	// Populate constants in to_hash and to_hash_point
	memcpy(&to_hash[0], BLSAG_ROUND_DOMAIN, BLSAG_ROUND_DOMAIN_SIZE);
	memcpy(&to_hash[BLSAG_ROUND_DOMAIN_SIZE], msg->bytes, sizeof(msg->bytes));
	memcpy(&to_hash_point[0], BLSAG_KIMG_DOMAIN, BLSAG_KIMG_DOMAIN_SIZE);
	
	// Calculate challenges
	c[0] = *c0;
	for (int j = 0; j < n; ++j) {
		int i = j & 1;
		
		// c[i] * K[i] + r[i] * G
		(void)! crypto_scalarmult_ristretto255(ci_Ki.bytes, c[i].bytes, K[j].bytes);
		crypto_scalarmult_ristretto255_base(ri_G.bytes, r[j].bytes);
		crypto_core_ristretto255_add(&to_hash[BLSAG_ROUND_DOMAIN_SIZE+32], ci_Ki.bytes, ri_G.bytes);
		
		// c[i] * Kimg + r[i] * Hp(K[i])
		(void)! crypto_scalarmult_ristretto255(ci_Kimg.bytes, c[i].bytes, Kimg->bytes);
		memcpy(&to_hash_point[BLSAG_KIMG_DOMAIN_SIZE], K[j].bytes, sizeof(K[j].bytes));
		hash_to_point_ristretto(&Hp_Ki, to_hash_point, sizeof(to_hash_point));
		(void)! crypto_scalarmult_ristretto255(ri_Hp_Ki.bytes, r[j].bytes, Hp_Ki.bytes);
		crypto_core_ristretto255_add(&to_hash[BLSAG_ROUND_DOMAIN_SIZE+32+32], ci_Kimg.bytes, ri_Hp_Ki.bytes);
		
		hash_to_scalar_ristretto(&c[i ^ 1], to_hash, sizeof(to_hash));
	}
	
	int accepted = 0 == sodium_memcmp(c[n & 1].bytes, c0->bytes, sizeof(Scalar));
	
	// Zeroize locals (some really don't need to be)
	sodium_memzero(ci_Ki.bytes, sizeof(Point));
	sodium_memzero(ri_G.bytes, sizeof(Point));
	sodium_memzero(ci_Kimg.bytes, sizeof(Point));
	sodium_memzero(Hp_Ki.bytes, sizeof(Point));
	sodium_memzero(ri_Hp_Ki.bytes, sizeof(Point));
	sodium_memzero(cpi_kpi.bytes, sizeof(Scalar));
	sodium_memzero(c, sizeof(c));
	sodium_memzero(to_hash, sizeof(to_hash));
	sodium_memzero(to_hash_point, sizeof(to_hash_point));
	
	return accepted;
}

void blsag_gen_key_image(
	Point *Kimg,
	const Scalar *k,
	const Point *K
) {
	Point Hp_K;
	uint8_t to_hash[BLSAG_KIMG_DOMAIN_SIZE + 32];
	
	memcpy(&to_hash[0], BLSAG_KIMG_DOMAIN, BLSAG_KIMG_DOMAIN_SIZE);
	memcpy(&to_hash[BLSAG_KIMG_DOMAIN_SIZE], K->bytes, sizeof(K->bytes));
	hash_to_point_ristretto(&Hp_K, to_hash, sizeof(to_hash));
	(void)! crypto_scalarmult_ristretto255(Kimg->bytes, k->bytes, Hp_K.bytes);
	
	sodium_memzero(Hp_K.bytes, sizeof(Point));
	sodium_memzero(to_hash, sizeof(to_hash));
}
