#include "blsag.h"
#include "sha3.h"
#include <sodium.h>
#include <stdio.h>

int main() {
	if (sodium_init() == -1) {
		puts("Sodium init failed");
		return 1;
	}
	
	Hash msg;
	sha3("Hello World!", sizeof("Hello World!") - 1, msg.bytes, sizeof(msg.bytes));
	
	int ring_size = 8;
	int pi = 5;
	
	Point ring[ring_size];
	Scalar kpi;
	for (int i = 0; i < ring_size; ++i) {
		if (i == pi) {
			crypto_core_ristretto255_scalar_random(kpi.bytes);
			crypto_scalarmult_ristretto255_base(ring[pi].bytes, kpi.bytes);
		} else {
			crypto_core_ristretto255_random(ring[i].bytes);
		}
	}
	
	Point Kimg;
	Scalar challenges[ring_size];
	Scalar responses[ring_size];
	
	blsag_sign(&msg, ring_size, pi, &kpi, &Kimg, ring, challenges, responses);
	int accepted = blsag_verify(&msg, ring_size, ring, &Kimg, &challenges[0], responses);
	printf("accepted = %d\n", accepted);
	return 0;
}
