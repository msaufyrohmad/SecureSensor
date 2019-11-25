/*
 * cilipadi.h
 *
 * CiliPadi lightweight authenticated encryption reference implementation.
 *
 * CiliPadi is owned by CyberSecurity Malaysia.
 * For enquiries, send an email to cilipadi at cybersecurity dot my
 */

#ifndef CILIPADI128V1_REF_CILIPADI_H_
#define CILIPADI128V1_REF_CILIPADI_H_

#define BYTERATE 8 // bitrate in bytes
#define AROUNDS 18 // number of rounds for P_{a,n}
#define BROUNDS 16 // number of rounds for P_{b,n}
#define STATELEN 32 // state size in bytes
//#define DEBUG
//#define DEBUGP // debug for the permutation function P - more detailed printouts
//#define OWNMAIN

void print_bytes(unsigned char *x, unsigned int start_index, unsigned int len, unsigned int newline);
int permutation_256(unsigned char *state, int rounds);
int permutation_384(unsigned char *state, int rounds);
int f_function(unsigned char *x, int l, int pround);
int xor_bytes(unsigned char *x, const unsigned char *y, int len);
int cilipadi_main();
#endif /* CILIPADI128V1_REF_CILIPADI_H_ */
