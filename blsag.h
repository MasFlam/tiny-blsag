// Tiny bLSAG signature implementation using mjosaarinen's tiny_sha3
// and libsodium ristretto255, released to the public domain.
// - Łukasz "masflam" Drukała, 2024-05-01

#ifndef _BLSAG_H_
#define _BLSAG_H_

#include <stdint.h>

// Hash domain tags
#define BLSAG_KIMG_DOMAIN "keyimg"
#define BLSAG_KIMG_DOMAIN_SIZE 6
#define BLSAG_ROUND_DOMAIN "blsag"
#define BLSAG_ROUND_DOMAIN_SIZE 5

typedef struct {
	uint8_t bytes[32];
} Point;

typedef struct {
	uint8_t bytes[32];
} Scalar;

typedef struct {
	uint8_t bytes[32];
} Hash;

void blsag_sign(
	const Hash *msg,
	int n,
	int pi,
	const Scalar *k_pi,
	Point *Kimg,
	const Point K[n],
	Scalar c[n],
	Scalar r[n]
);

// Return whether the signature is valid
int blsag_verify(
	const Hash *msg,
	int n,
	const Point K[n],
	const Point *Kimg,
	const Scalar *c0,
	const Scalar r[n]
);

void blsag_gen_key_image(
	Point *Kimg,
	const Scalar *k,
	const Point *K
);

#endif
