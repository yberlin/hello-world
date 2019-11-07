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
	uint32_t t[12];
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
	c[1] = (b[1] << 1) | ((b[1] & 0x80000000) >> 31);
	c[2] = (b[2] << 8) | ((b[2] & 0xFF000000) >> 24);
	c[3] = (b[3] << 11) | ((b[3] & 0xFFE00000) >> 21);
}
void Key_Schedule(unsigned char *Seedkey, int Keylen, unsigned char Direction, unsigned char *Subkey) {
	//Seedkey     密钥
	//Keylen      密钥比特长度
	//Direction:  0 加密，1 解密
	//Subkey      子密钥
	int i,j, r;
	uint32_t row[4], row_1[4],row_2[4];
	if (Keylen == 128)
	{
		for ( i = 0; i < 4; i++)
		{
			row[i] = 0;
		}
		//the first round subkey = seedkey
		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++)
			Subkey[i * 4 + j] = Seedkey[i * 4 + 3-j];
		printf("first round row[0]~row[4]\n");
		//8bit to 32bit
		for ( i = 0; i < 4; i++)
		{
			row[i] = row[i] | Seedkey[i * 4 ] | (Seedkey[i * 4 + 1] << 8) | (Seedkey[i * 4 + 2] << 16) | (Seedkey[i * 4 + 3] << 24);
			printf("%x\n", row[i]);
		}
		for ( r = 0; r < 44; r++)
		{
			//SubCloumn
			SubCloumn(row, row_1);
			//Feistel
			row_2[3] = row_1[0];
			row_2[0] = ((row_1[0] << 7) | (row_1[0] & 0xFE000000) >> 25) ^ row_1[1];
			row_2[1] = row_1[2];
			row_2[2] = ((row_1[2] << 17) | (row_1[2] & 0xFFFF8000) >> 15) ^ row_1[3];
			//round constant
			row_2[0] = row_2[0] ^ RC44[r];
			//128 key schedule
			//Subkey[0]--Subkey[3]->row_2[0]
			//Subkey[4]--Subkey[7]->row_2[1]
			for (i = 0; i < 4; i++)
			{	
				for ( j = 0; j < 4; j++) {
					Subkey[16 * (r + 1) + i * 4 + j] = (row_2[i] & (0xFF000000 >> (j * 8))) >> ((3-j) * 8);
				}				
			}
			//assign row_2 to row
			for (i = 0; i < 4; i++)
			{
				row[i] = row_2[i];
			}
		}
	}
	/*else if (Keylen == 256)
	{

	}
	else*/
		//printf("keylen is wrong");
}

void TANGRAM_128_128(unsigned char *input, int in_len, unsigned char *output, int out_len, unsigned char *key, int key_len) {
	uint32_t state[4],state_s[4],key_32[4];
	unsigned char subkey[16 * 45];
	int i, j;
	for (i = 0; i < 4; i++)
	{
		state[i] = 0;
		key_32[i] = 0;
	}
	for (i = 0; i < 4; i++)
	{
		state[i] = input[i * 4 ] | (input[i * 4 + 1] << 8) | (input[i * 4 + 2] << 16) | (input[i * 4 + 3] << 24);
	}
	//test printf
	printf("input:\n");
	for (i = 0; i < 4; i++)
	{
		printf("%x", state[i]);
		printf("\n");
	}
	//produce subkey
	Key_Schedule(key, 128, 0, subkey);
	//test printf
	printf("subkey:\n");
	for ( i = 0; i < 45; i++)
	{
		printf("round:%d\n", i);
		for (j = 0; j < 4; j++)
		{
			for (int n = 0; n < 4; n++)
			{
				printf("%2x ", subkey[i*16 + j*4 + n]);
			}
			printf("\n");
		}
	}
	//round function
	for (i = 0; i < 44; i++)
	{
		for(j=0;j<4;j++)
			key_32[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
		printf("round:%d \n", i);
		printf("state \n");
		for (int n = 0; n < 4; n++)
		{
			printf("%2x \n", state[n]);
		}
		printf("\n");
		printf("key_32 \n");
		for (int n = 0; n < 4; n++)
		{
			printf("%2x \n", key_32[n]);
		}
		printf("\n");
		AddRoundKey(state, key_32, state);
		printf("Addroundkey \n");
			for (int n = 0; n < 4; n++)
			{
				printf("%2x \n", state[n]);
			}
			printf("\n");
		
		SubCloumn(state, state_s);
		printf("Subcolumn \n");
			for (int n = 0; n < 4; n++)
			{
				printf("%2x \n", state_s[n ]);
			}
			printf("\n");
		
		ShiftRow(state_s, state);
		printf("Shiftrow \n");
			for (int n = 0; n < 4; n++)
			{
				printf("%2x \n", state[n]);
			}
			printf("\n");
		
	}
	//final add round 
	for (j = 0; j < 4; j++)
		key_32[j] = subkey[44 * 16 + j * 4 + 3] | (subkey[44 * 16 + j * 4 + 2] << 8) | (subkey[44 * 16 + j * 4 + 1] << 16) | (subkey[44 * 16 + j * 4 + 0] << 24);
	AddRoundKey(state, key_32, state);
	//trans state(32bit) to output(8bit)
	for (i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++) {
			output[ i*4 + 3 - j] = (state[i] & (0xFF000000 >> (j * 8))) >> ((3 - j) * 8);
		}

	}
}

