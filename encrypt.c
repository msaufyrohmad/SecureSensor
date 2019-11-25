/*
 * encrypt.c
 *
 * CiliPadi lightweight authenticated encryption reference implementation.
 *
 * CiliPadi is owned by CyberSecurity Malaysia.
 * For enquiries, send an email to cilipadi at cybersecurity dot my
 */

#include "crypto_aead.h"
#include "led.h"
#include "cilipadi.h"
#include "api.h"
#include <stdio.h>
#include <string.h> // for memcpy
#include <stdlib.h> // malloc() and free()

/*
 * print the array bytes
 * x           : array of bytes
 * start_index : start index of the array
 * len         : how many bytes to print
 * newline     : whether or not we want to print a newline (0 = no, 1 = yes)
 */
void print_bytes(unsigned char *x, unsigned int start_index, unsigned int len, unsigned int newline) {
	unsigned int i;

	for (i = start_index; i < len; ++i) {
		printf("%02x", x[i]);
	}
	if (newline) printf("\n");
}

/*
 * Initialization Phase
 * state : state bytes
 * npub  : public nonce
 * k     : secret key
 */
int init_phase(unsigned char *state, const unsigned char *npub, const unsigned char *k) {
	int i;

	// fill in the key
	for (i=0; i<CRYPTO_KEYBYTES; i++) {
		state[i] = k[i];
	}

	// fill in the nonce
	for (i=CRYPTO_KEYBYTES; i<STATELEN; i++) {
		state[i] = npub[i-CRYPTO_KEYBYTES];
	}

	permutation_256(state, AROUNDS);

	return 0;
}

/*
 * Associated Data Phase
 * state   : state bytes
 * state_r : the bitrate part of the state bytes
 * ad      : AD bytes
 * adlen   : length of AD
 */
int ad_phase(unsigned char *state, const unsigned char *ad, unsigned long long adlen) {
	unsigned char x[BYTERATE] = { 0 };

#ifdef DEBUG
	unsigned int maxblock = adlen / BYTERATE;
	printf("  S : ");
	print_bytes(state, 0, STATELEN, 1);
#endif

	while (adlen >= BYTERATE) {
		// XOR state with AD
		xor_bytes(state, ad, BYTERATE);

#ifdef DEBUG
		printf("  AD_{%d} : ", maxblock - (unsigned int)(adlen/BYTERATE));
		print_bytes((unsigned char *)ad, 0, BYTERATE, 1);

		printf("  after XOR with AD\n  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif

		permutation_256(state, BROUNDS);

		adlen -= BYTERATE;
		ad += BYTERATE;
	}

	xor_bytes(state, ad, adlen);

	x[adlen] = 0x80;

	xor_bytes(state, x, BYTERATE);

#ifdef DEBUG
		printf("  AD (last) : ");
		print_bytes((unsigned char *)ad, 0, adlen, 0);
		print_bytes(x, adlen, BYTERATE, 1);

		printf("  after XOR with AD\n  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif

	permutation_256(state, BROUNDS);

	return 0;
}

/*
 * Encryption / Decryption
 * state_r        : bitrate part of the state bytes
 * in             : input bytes (plaintext or ciphertext)
 * inlen          : length of input (padded)
 * unpadded_inlen : length of original input
 * out            : output bytes (ciphertext or decrypted ciphertext)
 * enc            : status whether 0 = decrypt or 1 = encrypt
 */
int ciphering_phase(unsigned char *state,
		const unsigned char *in,
		unsigned long long inlen,
		unsigned char *out,
		int enc) {
	unsigned char x[BYTERATE] = { 0 };

#ifdef DEBUG
	unsigned int maxblock = inlen / BYTERATE;
#endif

	// encryption
	if (enc == 1) {

		while (inlen >= BYTERATE) {
#ifdef DEBUG
			printf("  S (before XOR with In) : ");
			print_bytes(state, 0, STATELEN, 1);
#endif

			xor_bytes(state, in, BYTERATE);
			memcpy(out, state, BYTERATE);

#ifdef DEBUG
			printf("  M%2d: ", maxblock - (unsigned int)(inlen/BYTERATE));
			print_bytes((unsigned char *)in, 0, BYTERATE, 1);

			printf("  C%2d: ", maxblock - (unsigned int)(inlen/BYTERATE));
			print_bytes((unsigned char *)out, 0, BYTERATE, 1);

			printf("  S (after XOR with In)  : ");
			print_bytes(state, 0, STATELEN, 1);
#endif

			permutation_256(state, BROUNDS);

			inlen -= BYTERATE;
			in += BYTERATE;
			out += BYTERATE;
		}
	}
	else {
		// decryption
		// note: "in" includes the ciphertext (if any) and tag
		while (inlen >= (CRYPTO_ABYTES + BYTERATE)) {
#ifdef DEBUG
			printf("  S (before XOR with In) : ");
			print_bytes(state, 0, STATELEN, 1);
#endif
			memcpy(out, state, BYTERATE);

			xor_bytes(out, in, BYTERATE);
			memcpy(state, in, BYTERATE);

#ifdef DEBUG
			printf("  C%2d: ", maxblock - (unsigned int)(inlen/BYTERATE));
			print_bytes((unsigned char *)in, 0, BYTERATE, 1);

			printf("  M%2d: ", maxblock - (unsigned int)(inlen/BYTERATE));
			print_bytes((unsigned char *)out, 0, BYTERATE, 1);

			printf("  S (after XOR with In)  : ");
			print_bytes(state, 0, STATELEN, 1);
#endif

			permutation_256(state, BROUNDS);

			inlen -= BYTERATE;
			in += BYTERATE;
			out += BYTERATE;
		}

	}


	if (enc == 1) {
		xor_bytes(state, in, inlen);

		// copy BYTERATE bytes of state to out
		memcpy(out, state, BYTERATE);

		x[inlen] = 0x80;

		xor_bytes(state, x, BYTERATE);

#ifdef DEBUG
		printf("inlen = %llu\n", inlen);

		printf("  x : ");
		print_bytes(x, 0, BYTERATE, 1);

		printf("  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif


#ifdef DEBUG
		printf("  M (last) : ");
		print_bytes((unsigned char *)in, 0, inlen, 1);

		printf("  C (last): ");
		print_bytes((unsigned char *)out, 0, inlen, 1);
#endif
	}
	else {
		// the last ciphertext block
		x[inlen % CRYPTO_ABYTES] = 0x80;

#ifdef DEBUG
		printf("inlen = %llu\n", inlen);
#endif

		if (inlen > CRYPTO_ABYTES) {
#ifdef DEBUG
			printf("inlen > CRYPTO_ABYTES\n");
#endif
			for (int i = 0; i < (inlen - CRYPTO_ABYTES); ++i) {
#ifdef DEBUG
#endif
				out[i] = state[i] ^ in[i];
				state[i] = in[i];
			}
		}

#ifdef DEBUG
		printf("  x : ");
		print_bytes(x, 0, BYTERATE, 1);

		printf("  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif

		xor_bytes(state, x, BYTERATE);

#ifdef DEBUG
		printf("  C (last) : ");
		print_bytes((unsigned char *)in, 0, (inlen - CRYPTO_ABYTES), 0);

		printf("  M (last): ");
		print_bytes((unsigned char *)out, 0, (inlen - CRYPTO_ABYTES), 1);
#endif
	}

#ifdef DEBUG

		printf("  after XOR with In\n  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif

	return 0;
}

/*
 * Finalization Phase
 * state : state bytes
 * k     : secret key bytes
 */
int finalization_phase(unsigned char *state, const unsigned char *k) {

#ifdef DEBUG
	printf("  S : ");
	print_bytes(state, 0, STATELEN, 1);
#endif

	permutation_256(state, AROUNDS);

	// XOR with key
	xor_bytes(state, k, CRYPTO_KEYBYTES);

	return 0;
}

/*
 * the code for the AEAD implementation goes here,
 *
 * generating a ciphertext c[0],c[1],...,c[*clen-1]
 * from a plaintext m[0],m[1],...,m[mlen-1]
 * and associated data ad[0],ad[1],...,ad[adlen-1]
 * and nonce npub[0],npub[1],...
 * and secret key k[0],k[1],...
 * the implementation shall not use nsec
 *
 */
int crypto_aead_encrypt(
	unsigned char *c,
	unsigned long long *clen,
	const unsigned char *m,
	unsigned long long mlen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k) {

	unsigned char state[STATELEN]; // state
	int i;

	/*
	 * Initialization
	 */
#ifdef DEBUG
	printf("-- INIT PHASE --\n");
#endif
	init_phase(state, npub, k);

	/*
	 * Processing the associated data
	 */
#ifdef DEBUG
	printf("\n-- AD PHASE --\n");
#endif

	if (adlen > 0)
		ad_phase(state, ad, adlen);

	// XOR the last bit of the state with '1' to indicate completion of AD phase
	state[STATELEN-1] ^= 1;

#ifdef DEBUG
		printf("  end of AD Phase\n  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif

	/*
	 * Processing the plaintext
	 */
#ifdef DEBUG
	printf("\n-- MESSAGE ENCRYPTION PHASE --\n");
#endif
	ciphering_phase(state, m, mlen, c, 1);

	/*
	 * Finalization Phase
	 */
#ifdef DEBUG
	printf("\n-- FINALIZATION PHASE --\n");
#endif
	finalization_phase(state, k);

	// output the tag
	*clen = mlen + CRYPTO_ABYTES;
	for (i = 0; i < CRYPTO_ABYTES; ++i) {
		c[mlen+i] = state[i];
	}

	return 0;
}

/*
 * the code for the AEAD implementation goes here,
 *
... generating a plaintext m[0],m[1],...,m[*mlen-1]
... and secret message number nsec[0],nsec[1],...
... from a ciphertext c[0],c[1],...,c[clen-1]
... and associated data ad[0],ad[1],...,ad[adlen-1]
... and nonce number npub[0],npub[1],...
... and secret key k[0],k[1],... ...
 */

int crypto_aead_decrypt(
	unsigned char *m,
	unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,
	unsigned long long clen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k) {

	unsigned char state[STATELEN]; // 16-byte state
	int i;
	unsigned char tag[CRYPTO_ABYTES]; // computed tag

	/*
	 * Initialization
	 */
#ifdef DEBUG
	int j;
	printf("\n-- INIT PHASE --\n");
#endif
	init_phase(state, npub, k);

	/*
	 * Processing the associated data
	 */

#ifdef DEBUG
	printf("\n-- AD PHASE --\n");
#endif

	if (adlen > 0)
		ad_phase(state, ad, adlen);

	// XOR the last bit of the state with '1' to indicate completion of AD phase
	state[STATELEN-1] ^= 1;

#ifdef DEBUG
		printf("  end of AD Phase\n  S : ");
		print_bytes(state, 0, STATELEN, 1);
#endif

	/*
	 * Processing the ciphertext
	 */
#ifdef DEBUG
	printf("\n-- MESSAGE DECRYPTION PHASE --\n");
#endif
	ciphering_phase(state, c, clen, m, 0);

	/*
	 * Finalization Phase
	 */
#ifdef DEBUG
	printf("\n-- FINALIZATION PHASE --\n");
#endif
	finalization_phase(state, k);

	// output the tag
	if (clen < CRYPTO_ABYTES) { // if the ciphertext is empty
		*mlen = 0;
	}
	else {
		*mlen = clen - CRYPTO_ABYTES;
	}
#ifdef DEBUG
	printf("\nKey          : ");
	print_bytes((unsigned char *)k, 0, CRYPTO_KEYBYTES, 1);
	printf("Computed Tag : ");
#endif
	for (i = 0; i < CRYPTO_ABYTES; ++i) {
		tag[i] = state[i];
#ifdef DEBUG
		printf("%02x", tag[i]);
#endif
	}

#ifdef DEBUG
	printf("\n");
#endif

	// compare computed tag with the one received
	for (i = 0; i < CRYPTO_ABYTES; ++i) {
		if (tag[i] != c[*mlen+i]) {

#ifdef DEBUG
			printf("Ciphertext not authenticated!\n");
			printf("clen: %llu; mlen: %llu\n", clen, *mlen);
			printf("Message   : "); for (j=0; j<*mlen; j++) printf("%02x", m[j]); printf("\n");
			printf("AD        : "); for (j=0; j<adlen; j++) printf("%02x", ad[j]); printf("\n");
			printf("Key       : "); for (j=0; j<CRYPTO_KEYBYTES; j++) printf("%02x", k[j]); printf("\n");
			printf("Ciphertext: "); for (j=0; j<clen; j++) printf("%02x", c[j]); printf("\n");
			printf("Tag in Ct : ");
			for (j = 0; j < CRYPTO_ABYTES; ++j) {
				printf("%02x", c[*mlen+j]);
			}
			printf("\n");
#endif
			return -1;
		}
	}

	return 0;
}
