#include <stdint.h>
#include "TANGRAM.h"
void AddRoundKey(uint32_t* input, uint32_t* sk, uint32_t* a) {
	for (int i = 0; i < 4; i++)
	{
		a[i] = input[i]^ sk[i];
	}
	

}

void SubCloumn(uint32_t *a, uint32_t *b) {
	uint32_t t[11];
	t[1] = a[0] ^ a[2];
	t[2] = a[0] & a[1];
	t[3] = a[3] ^ t[2];
	b[2] = a[2] ^ t[3];
	t[5] = a[1] ^ a[2];
	t[6] = t[1] & t[3];
	b[0] = t[5] ^ t[6];
	t[8] = a[1] | a[3];
	t[9] = t[1] ^ t[8];
	b[3] = ~t[9];
	t[11] = t[5] & t[9];
	b[1] = t[3] ^ t[11];
}

void ShiftRow(uint32_t *b, uint32_t *c) {
	c[0] = b[0];
	c[1] = (b[1] << 1) | (b[1] & 0x80000000 >> 31);
	c[2] = (b[2] << 8) | (b[2] & 0xFF000000 >> 24);
	c[3] = (b[3] << 11) | (b[3] & 0xFFE00000 >> 21);
}
void Keyschedule
void TANGRAM_128_128(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)