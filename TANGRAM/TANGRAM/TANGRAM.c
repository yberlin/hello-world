#include <stdint.h>
#include "TANGRAM.h"
//input should be :[v31, .......v2, v1, v0]
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
void Key_Schedule(unsigned char *Seedkey, int Keylen, unsigned char Direction, unsigned char *Subkey) {
	//Seedkey     密钥
	//Keylen      密钥比特长度
	//Direction:  0 加密，1 解密
	//Subkey      子密钥
	int i, r;
	uint32_t row[4], row_1[4],row_2[4];
	if (Keylen == 128)
	{
		for ( i = 0; i < 4; i++)
		{
			row[4] = 0;
		}
		//8bit to 32bit
		for ( i = 0; i < 4; i++)
		{
			row[i] = row[i] | Seedkey[i * 4 + 3] | (Seedkey[i * 4 + 2] << 8) | (Seedkey[i * 4 + 1] << 16) | (Seedkey[i * 4 + 0] << 24);
		}
		for ( r = 0; r < 44; r++)
		{
			//ShiftRow
			ShiftRow(row, row_1);
			//Feistel
			row_2[3] = row_1[0];
			row_2[0] = ((row_1[0] << 7) | row_1[0] & 0xFE000000 >> 25) ^ row_1[1];
			row_2[1] = row_1[2];
			row_2[2] = ((row_1[2] << 17) | row_1[2] & 0xFFFF8000 >> 15) ^ row_1[3];
			//round constant
			row_2[0] = row_2[0] ^ RC44[r];
		}
		for (i = 0; i < 4; i++)
		{

		}
	}
	else if (Keylen == 256)
	{

	}
	else
		printf("keylen is wrong");
}
void TANGRAM_128_128(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)