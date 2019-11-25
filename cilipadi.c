/*
 * cilipadi.c
 *
 * CiliPadi lightweight authenticated encryption reference implementation.
 *
 * CiliPadi is owned by CyberSecurity Malaysia.
 * For enquiries, send an email to cilipadi at cybersecurity dot my
 */

#include <stdio.h>
#include "cilipadi.h"
#include "led.h"
#include "crypto_aead.h"
#include <string.h> // for memcpy
#include <stdlib.h> // for malloc(), free()
#include "api.h"
#include "cilipadi.h"

/*
 * XOR two byte arrays
 * x   : first array
 * y   : second array
 * len : length of array to XOR
 */
int xor_bytes(unsigned char *x, const unsigned char *y, int len) {
	int i;

	for (i = 0; i < len; ++i) {
		x[i]^=y[i];
	}

	return 0;
}

/*
 * The Permutation P_{256}
 * state  : state bytes
 * rounds : number of rounds
 */
int permutation_256(unsigned char *state, int rounds) {
	unsigned char x1[8];
	unsigned char x2[8];
	unsigned char x3[8];
	unsigned char x4[8];
	unsigned char temp[8];
	int i;

	// divide the input into 4 branches
	for (i = 0; i < 8; ++i) {
		x1[i] = state[i];
		x2[i] = state[i+8];
		x3[i] = state[i+16];
		x4[i] = state[i+24];
	}

	for (i = 0; i < rounds; ++i) {

#ifdef DEBUGP
		printf("\n  S (R%2d input) : ", i+1);

		print_bytes(x1, 0, 8, 0); printf(" ");
		print_bytes(x2, 0, 8, 0); printf(" ");
		print_bytes(x3, 0, 8, 0); printf(" ");
		print_bytes(x4, 0, 8, 1);
#endif

		memcpy(temp, x1, 8);
		f_function(temp, 1, i);
		xor_bytes(x2, temp, 8);

		memcpy(temp, x3, 8);
		f_function(temp, 2, i);
		xor_bytes(x4, temp, 8);

		// shuffle
		memcpy(temp, x1, 8);
		memcpy(x1, x2, 8); // x2 -> x1
		memcpy(x2, x3, 8); // x3 -> x2
		memcpy(x3, x4, 8); // x4 -> x3
		memcpy(x4, temp, 8); // temp -> x4


#ifdef DEBUGP
		printf("  S (R%2d output): ", i+1);

		print_bytes(x1, 0, 8, 0); printf(" ");
		print_bytes(x2, 0, 8, 0); printf(" ");
		print_bytes(x3, 0, 8, 0); printf(" ");
		print_bytes(x4, 0, 8, 1);
#endif
	}

	// put value back to state
	for (i = 0; i < 8; ++i) {
		state[i   ] = x1[i];
		state[i+ 8] = x2[i];
		state[i+16] = x3[i];
		state[i+24] = x4[i];
	}

	return 0;
}

/*
* The Permutation P_{384}
* state  : state bytes
* rounds : number of rounds
*/
int permutation_384(unsigned char *state, int rounds) {
	unsigned char x1[8];
	unsigned char x2[8];
	unsigned char x3[8];
	unsigned char x4[8];
	unsigned char x5[8];
	unsigned char x6[8];
	unsigned char temp[8];
	int i;

	// divide the input into 6 branches
	for (i = 0; i < 8; ++i) {
		x1[i] = state[i];
		x2[i] = state[i+8];
		x3[i] = state[i+16];
		x4[i] = state[i+24];
		x5[i] = state[i+32];
		x6[i] = state[i+40];
	}

	for (i = 0; i < rounds; ++i) {

#ifdef DEBUGP
		printf("\n  S (R%2d input) : ", i+1);

		print_bytes(x1, 0, 8, 0); printf(" ");
		print_bytes(x2, 0, 8, 0); printf(" ");
		print_bytes(x3, 0, 8, 0); printf(" ");
		print_bytes(x4, 0, 8, 0); printf(" ");
		print_bytes(x5, 0, 8, 0); printf(" ");
		print_bytes(x6, 0, 8, 1);
#endif

		memcpy(temp, x1, 8);
		f_function(temp, 1, i);
		xor_bytes(x2, temp, 8);

		memcpy(temp, x3, 8);
		f_function(temp, 2, i);
		xor_bytes(x4, temp, 8);

		memcpy(temp, x5, 8);
		f_function(temp, 3, i);
		xor_bytes(x6, temp, 8);


		// shuffle
		memcpy(temp, x1, 8);
		memcpy(x1, x2, 8); // x2 -> x1
		memcpy(x2, x3, 8); // x3 -> x2
		memcpy(x3, x6, 8); // x6 -> x3
		memcpy(x6, x5, 8); // x5 -> x6
		memcpy(x5, x4, 8); // x4 -> x5
		memcpy(x4, temp, 8); // temp -> x4

#ifdef DEBUGP
		printf("\n  S (R%2d output): ", i+1);

		print_bytes(x1, 0, 8, 0); printf(" ");
		print_bytes(x2, 0, 8, 0); printf(" ");
		print_bytes(x3, 0, 8, 0); printf(" ");
		print_bytes(x4, 0, 8, 0); printf(" ");
		print_bytes(x5, 0, 8, 0); printf(" ");
		print_bytes(x6, 0, 8, 1);
#endif
	}

	// put value back to state
	for (i = 0; i < 8; ++i) {
		state[i   ] = x1[i];
		state[i+ 8] = x2[i];
		state[i+16] = x3[i];
		state[i+24] = x4[i];
		state[i+32] = x5[i];
		state[i+40] = x6[i];
	}

	return 0;
}

/*
 * The F-Function
 * x      : input to the F-function
 * l      : F_l where l = {1, 2}
 * pround : the permutation round
 */
int f_function(unsigned char *x, int l, int pround) {
	unsigned char led_state[4][4];
	int i, j, k, rounds=2;
	const unsigned char RC[48] = {
		0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
		0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
		0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
		0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
		0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04
	};
	unsigned RC_state[4][4] = {
		{ 0, 0, 0, 0 },
		{ 0, 0, 0, 0 },
		{ 2, 0, 0, 0 },
		{ 3, 0, 0, 0 }
	};

#ifdef DEBUGP
	printf("    -- F%2d --\n", l);
	printf("    input: ");
	print_bytes(x, 0, 8, 1);
#endif
	// decompose input into LED 4x4 state bytes
	for (i = 0; i < 16; ++i) {
		if(i%2) led_state[i/4][i%4] = x[i>>1]&0xF;
		else led_state[i/4][i%4] = (x[i>>1]>>4)&0xF;
	}

	for (i = 0; i < rounds; ++i) {

#ifdef DEBUGP
		printf("    LED round %d\n", i+1);
		printf("    input:\n");
		for (j=0; j<4; j++) {
			printf("    ");
			for (k=0; k<4; k++) {
				printf("%x ", led_state[j][k]);
			}
			printf("\n");
		}
#endif
		// note that the implemented LED is v2 which require the XOR of the key length (i.e. 64 or 128 bits)
		// to the first column of the state.
		// We do not require this and hence, we have modified LED's source code so that we only use round constants for round 1 LED
		//AddConstantsCiliPadi(led_state, i, l);

		RC_state[0][0] ^= ((l>>2) & 0x3);
		RC_state[1][0] ^= ( l     & 0x3);

		unsigned char tmp = (RC[pround] >> 3) & 7;

		RC_state[0][1] ^= tmp;
		RC_state[2][1] ^= tmp;
		tmp =  RC[pround] & 7;
		RC_state[1][1] ^= tmp;
		RC_state[3][1] ^= tmp;

		if (i > 0) {
			for (j=0; j<4; j++) for (k=0; k<4; k++) RC_state[j][k] = 0;
		}

		// AddConstants CiliPadi
		for (j = 0; j < 4; ++j) {
			for (k = 0; k < 2; ++k) {
				led_state[j][k] ^= RC_state[j][k];
			}
		}

#ifdef DEBUGP
		printf("    round constants:\n");
		for (j=0; j<4; j++) {
			printf("    ");
			for (k=0; k<4; k++) {
				printf("%x ", RC_state[j][k]);
			}
			printf("\n");
		}

		printf("    after AC:\n");
		for (j=0; j<4; j++) {
			printf("    ");
			for (k=0; k<4; k++) {
				printf("%x ", led_state[j][k]);
			}
			printf("\n");
		}
#endif
		SubCell(led_state);
#ifdef DEBUGP
		printf("    after SC:\n");
		for (j=0; j<4; j++) {
			printf("    ");
			for (k=0; k<4; k++) {
				printf("%x ", led_state[j][k]);
			}
			printf("\n");
		}
#endif
		ShiftRow(led_state);
#ifdef DEBUGP
		printf("    after SR:\n");
		for (j=0; j<4; j++) {
			printf("    ");
			for (k=0; k<4; k++) {
				printf("%x ", led_state[j][k]);
			}
			printf("\n");
		}
#endif
		MixColumn(led_state);
#ifdef DEBUGP
		printf("    after MCS:\n");
		for (j=0; j<4; j++) {
			printf("    ");
			for (k=0; k<4; k++) {
				printf("%x ", led_state[j][k]);
			}
			printf("\n");
		}
#endif
	}

	// put back into x
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 2; ++j) {
			x[i*2+j]  = led_state[i][j*2  ] << 4;
			x[i*2+j] |= led_state[i][j*2+1];
		}
	}

#ifdef DEBUGP
	printf("    output: ");
	print_bytes(x, 0, 8, 1);
#endif

	return 0;
}


//#ifdef OWNMAIN
int main() {
	unsigned char c[48];
	unsigned long long clen;

	//const unsigned char m[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	
	// test vector value
//	const unsigned char m[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	//unsigned char *m_dec;
	unsigned char m_dec[8];
	//unsigned char m_dec[32];

	//unsigned long long mlen = BYTERATE+8-1;
	//unsigned long long mlen = 16;
	unsigned long long mlen_dec;

	//const unsigned char ad[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	//const unsigned char ad[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	// test vector value
	//const unsigned char ad[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	//unsigned long long adlen = BYTERATE;
	//unsigned long long adlen = 16;

	const unsigned char npub[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	// test vector value
	//const unsigned char npub[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	const unsigned char k[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	// test vector value
	//const unsigned char k[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	int i;
	
	const unsigned char m[8]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	unsigned long long mlen = 8;
	const unsigned char ad[8]={0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x00};
	unsigned long long adlen = 8;

	crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);

	printf("\nENCRYPTION\n");

	printf("\nPlaintext  : ");
	for (i = 0; i < mlen; ++i) {
		printf("%02x", m[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nKey        : ");
	for (i = 0; i < CRYPTO_KEYBYTES; ++i) {
		printf("%02x", k[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nNonce      : ");
	for (i = 0; i < (STATELEN - CRYPTO_KEYBYTES); ++i) {
		printf("%02x", npub[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nAD         : ");
	for (i = 0; i < adlen; ++i) {
		printf("%02x", ad[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nCiphertext : ");
	for (i = 0; i < (clen - CRYPTO_ABYTES); ++i) {
		printf("%02x", c[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nTag        : ");
	for (i = 0; i < CRYPTO_ABYTES; ++i) {
		printf("%02x", c[(clen - CRYPTO_ABYTES)+i]);
	}


	printf("\n\nDECRYPTION\n");

	printf("\nCiphertext : ");
	for (i = 0; i < (clen - CRYPTO_ABYTES); ++i) {
		printf("%02x", c[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nKey        : ");
	for (i = 0; i < CRYPTO_KEYBYTES; ++i) {
		printf("%02x", k[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	printf("\nNonce      : ");
	for (i = 0; i < (STATELEN - CRYPTO_KEYBYTES); ++i) {
		printf("%02x", npub[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}

	// tamper
	//c[0] ^=1;
	if (crypto_aead_decrypt(m_dec, &mlen_dec, NULL, c, clen, ad, adlen, npub, k) == 0) {
		printf("\nPlaintext  : ");
		for (i = 0; i < mlen_dec; ++i) {
			printf("%02x", m_dec[i]);
			if (((i+1)%BYTERATE) == 0)
				printf(" ");
		}

		printf("\nAD         : ");
		for (i = 0; i < adlen; ++i) {
			printf("%02x", ad[i]);
			if (((i+1)%BYTERATE) == 0)
				printf(" ");
		}
	}
	else {
		printf("Decryption failed\n");
	}

	printf("\nPlaintext  : ");
	for (i = 0; i < mlen; ++i) {
		printf("%02x", m[i]);
		if (((i+1)%BYTERATE) == 0)
			printf(" ");
	}


	return 0;
}
//#endif
