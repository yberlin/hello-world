#include <stdint.h>
#include "TANGRAM.h"

int Crypt_Enc_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//ECB模式加密
{
		TANGRAM_256_256_enc_Block(input, in_len, output, key, key_len);
		*out_len = in_len;
		return 0;
}
int Crypt_Dec_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//ECB模式解密
{
	TANGRAM_256_256_dec_Block(input, in_len, output, key, key_len);
	*out_len = in_len;
	return 0;
}
int Crypt_Enc_Block_Round(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len, int CryptRound)
{
	TANGRAM_256_256_enc_Round(input, in_len, output, key, key_len, CryptRound);
	*out_len = in_len;
	return 0;
}

int Crypt_Enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len) {
	unsigned char iv[32] = { 0x00 };
	
	TANGRAM_256_256_enc_Block_CBC(input, in_len, output, key, key_len, iv);
	*out_len = in_len;
	return 0;
}
int Crypt_Dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
{
	unsigned char iv[32] = { 0x00 };

	TANGRAM_256_256_dec_Block_CBC(input, in_len, output, key, key_len, iv);
	*out_len = in_len;
	return 0;
}
void AddRoundKey(uint64_t* input, uint64_t* sk, uint64_t* a) {
	for (int i = 0; i < 4; i++)
	{
		a[i] = input[i]^ sk[i];
	}
}

void SubCloumn(uint64_t *a, uint64_t *b) {
	uint64_t t[12];
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
void invSubcolumn(uint64_t *a, uint64_t *b) {
	uint64_t t[13];
	t[1] = ~a[3];
	t[2] = a[0] & t[1];
	t[3] = a[1] ^ t[2];
	b[2] = a[2] ^ t[3];
	t[5] = a[0] ^ a[2];
	t[6] = t[1] & t[3];
	b[1] = t[5] ^ t[6];
	t[8] = a[0] ^ t[1];
	t[9] = t[3] & t[5];
	b[0] = t[8] ^ t[9];
	t[11] = b[1] & b[0];
	b[3] = t[3] ^ t[11];
}

void ShiftRow(uint64_t *b, uint64_t *c) {
	c[0] = b[0];
	c[1] = (b[1] << 1) | ((b[1] & 0x8000000000000000) >> 63);
	c[2] = (b[2] << 8) | ((b[2] & 0xFF00000000000000) >> 56);
	c[3] = (b[3] << 41) | ((b[3] & 0xFFFFFFFFFF800000) >> 23);
}

void invShiftRow(uint64_t *b, uint64_t *c) {
	c[0] = b[0];
	c[1] = (b[1] >> 1) | ((b[1] & 0x0000000000000001) << 63);
	c[2] = (b[2] >> 8) | ((b[2] & 0x00000000000000FF) << 56);
	c[3] = (b[3] >> 41) | ((b[3] & 0x000001FFFFFFFFFF) << 23);
}
void Key_Schedule(unsigned char *Seedkey, int Keylen, unsigned char Direction, unsigned char *Subkey) {
	//Seedkey     密钥
	//Keylen      密钥比特长度
	//Direction:  0 加密，1 解密
	//Subkey      子密钥
	int i,j, r;
	unsigned char *in = Seedkey;
	uint64_t row[4], row_1[4],row_2[4];
	uint64_t temp[4];
	if (Keylen == 256)
	{
		uint64_t key_256_256[82][4] = { 0x00 };
		for ( i = 0; i < 4; i++)
		{
			row[i] = 0;
		}
		//the first round subkey = first 32 seedkey ,4 row 8 column
		for (i = 0; i < 4; i++)
			for (j = 0; j < 8; j++)
			{
				Subkey[i * 8 + 7 -j] = Seedkey[i * 8 + 7 - j];
				//printf("%2x ", Subkey[i * 8 + j]);
			};
		//8bit to 32bit
		
		//temp[1] = Seedkey[28] | (Seedkey[29] << 8) | (Seedkey[30] << 16) | (Seedkey[31] << 24);
		//printf("%llx \n", temp[1]);
		//temp[0]=  Seedkey[2 * 8] | (Seedkey[2 * 8 + 1] << 8) | (Seedkey[2 * 8 + 2] << 16) | (Seedkey[2 * 8 + 3] << 24) | ((uint64_t)(Seedkey[2 * 8 + 4]) << 32) | ((uint64_t)(Seedkey[2 * 8 + 5]) << 40) | ((uint64_t)(Seedkey[2 * 8 + 6]) << 48) | ((uint64_t)(Seedkey[2 * 8 + 7]) << 56);
		//printf("%llx \n", temp[0]);
		/*for ( i = 0; i < 4; i++)
		{
			row[i] = Seedkey[i * 8] | (Seedkey[i * 8 + 1] << 8) | (Seedkey[i * 8 + 2] << 16) | (Seedkey[i * 8 + 3] << 24) | ((uint64_t)(Seedkey[i * 8 + 4]) << 32) | ((uint64_t)(Seedkey[i * 8 + 5]) << 40) | ((uint64_t)(Seedkey[i * 8 + 6]) << 48) | ((uint64_t)(Seedkey[i * 8 + 7]) << 56);
			
		}
		row[3] = (row[3] & 0x00000000FFFFFFFF) ^ (temp[1] << 32);*/
		input_1Block(row[0], row[1], row[2], row[3], in);
		//printf("row\n");
		//for (i = 0; i < 4; i++)
			//printf("%llx \n", row[i]);
		for ( r = 0; r < 82; r++)
		{
			//printf("round %d key\n", r);
			//printf("subcolumn\n");
			//SubCloumn
			SubCloumn(row, row_1);
			
			//for (i = 0; i < 4; i++)
				//printf("%llx \n", row_1[i]);
			
			//Feistel
			//printf("Feistel\n");
			row_2[3] = row_1[0];
			row_2[0] = rol64(row_1[0], 7) ^ row_1[1];
			//row_2[0] = ((row_1[0] << (uint64_t)(7)) | (row_1[0] & 0xFE00000000000000) >> (uint64_t)57) ^ row_1[1];
			row_2[1] = row_1[2];
			//row_2[2] = ((row_1[2] << (uint64_t)17) | (row_1[2] & 0xFFFF800000000000) >> (uint64_t)47) ^ row_1[3];
			row_2[2] = rol64(row_1[2], 17) ^ row_1[3];
			//for (i = 0; i < 4; i++)
				//printf("%llx \n", row_2[i]);
			//round constant
			row_2[0] = row_2[0] ^ RC82[r];
			//printf("round constant\n");
			//for (i = 0; i < 4; i++)
				//printf("%llx \n", row_2[i]);
			//256 key schedule
			//Subkey[0]--Subkey[7]->row_2[0]
			//Subkey[8]--Subkey[15]->row_2[1]
			for (i = 0; i < 4; i++)
			{	
				for ( j = 0; j < 8; j++) {
					Subkey[32 * (r + 1) + i * 8 + (7-j)] = (row_2[i] & (0xFF00000000000000 >> (j * 8))) >> ((7-j) * 8);
					//printf("%2x ", Subkey[32 * (r + 1) + i * 8 + (7 - j)]);
				}	//printf("\n ");
			}
			//assign row_2 to row
			for (i = 0; i < 4; i++)
			{
				row[i] = row_2[i];
			}
		}
     }
	else
		printf("keylen is wrong");
}

void TANGRAM_256_256_enc_Block(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len) {
	//ECB
	unsigned char *in = input; unsigned char *out = output;
	unsigned char *sub;
	uint64_t state[4],state_s[4],key_64[4];
	unsigned char subkey[32 * 83];
	int block_cnt = in_len / BLOCK_SIZE_256;
	int i, j;
	//produce subkey
	Key_Schedule(key, key_len, 0, subkey);
	//printf("input[0]= %x\n", temp_in[0]);
	//printf("keyschedule successful");
	//block enc
	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 4; i++)
		{
			state[i] = 0;
			key_64[i] = 0;
		};
		input_1Block(state[0], state[1], state[2], state[3], in);
		//printf("input[0]= %x\n", temp[0]);
		//for (i = 0; i < 4; i++)//state origin
		//{
		//	state[i] = input[b * 32 + i * 8] | (input[b * 32 + i * 8 + 1] << 8) | (input[b * 32 + i * 8 + 2] << 16) | (input[b * 32 + i * 8 + 3] << 24) | ((uint64_t)(input[b * 32 + i * 8 + 4]) << 32) | ((uint64_t)(input[b * 32 + i * 8 + 5]) << 40) | ((uint64_t)(input[b * 32 + i * 8 + 6]) << 48) | ((uint64_t)(input[b * 32 + i * 8 + 7]) << 56);
		//}//same as key schedule row[i] = Seedkey[i * 4] | (Seedkey[i * 4 + 1] << 8) | (Seedkey[i * 4 + 2] << 16) | (Seedkey[i * 4 + 3] << 24) | ((uint64_t)Seedkey[i * 4 + 3] << 32) | ((uint64_t)Seedkey[i * 4 + 3] << 40) | ((uint64_t)Seedkey[i * 4 + 3] << 48) | ((uint64_t)Seedkey[i * 4 + 3] << 56);
		//printf("\n round 0 state0 \n", i);
		//for (i = 0; i < 4; i++)
			//printf("%llx \n", state[i]);
		sub = subkey;
		//round function
		for (i = 0; i < RC; i++)
		{
			//for (j = 0; j < 4; j++)
				//key_64[j] = subkey[i * 32 + j * 8 +7] | (subkey[i * 32 + j * 8 + 6] << 8) | (subkey[i * 32 + j * 8 + 5] << 16) | (subkey[i * 32 + j * 8 + 4] << 24) | ((uint64_t)subkey[i * 32 + j * 8 + 3] << 32) | ((uint64_t)subkey[i * 32 + j * 8 + 2] << 40) | ((uint64_t)subkey[i * 32 + j * 8 + 1] << 48) | ((uint64_t)subkey[i * 32 + j * 8 + 0] << 56);
				input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
			//printf("\n round %d key_64 \n", i);
			//for (int k = 0; k < 4; k++)
				//printf("%llx \n", key_64[k]);
			//printf("\n round %d state \n", i);
			//for (int k = 0; k < 4; k++)
				//printf("%llx \n", state[k]);
			sub = sub + 32;
			AddRoundKey(state, key_64, state);

			SubCloumn(state, state_s);

			ShiftRow(state_s, state);
			printf("\n round %d  shiftrow state \n", i);
			for (int k = 0; k < 4; k++)
				printf("%llx \n", state[k]);
		}
		//final add round 
		//for (j = 0; j < 4; j++)
			//key_64[j] = subkey[RC * 32 + j * 8 + 7] | (subkey[RC * 32 + j * 8 + 6] << 8) | (subkey[RC * 32 + j * 8 + 5] << 16) | (subkey[RC * 32 + j * 8 + 4] << 24) | ((uint64_t)subkey[RC * 32 + j * 8 + 3] << 32) | ((uint64_t)subkey[RC * 32 + j * 8 + 2] << 40) | ((uint64_t)subkey[RC * 32 + j * 8 + 1] << 48) | ((uint64_t)subkey[RC * 32 + j * 8 ] << 56);
		input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
		AddRoundKey(state, key_64, state);
		//trans state(64bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 8; j++) {
				output[16 * b + i * 8 + 7 - j] = (state[i] & (0xFF00000000000000 >> (j * 8))) >> ((7 - j) * 8);
			}
		}
	}
}

void TANGRAM_256_256_dec_Block(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len) {
	//ECB
	uint64_t state[4], state_s[4], key_64[4];
	unsigned char subkey[32 * 83];
	unsigned char *in = input; unsigned char *out = output;
	unsigned char *sub;
	int i, j;
	int block_cnt = in_len / BLOCK_SIZE_256;
	//produce subkey
	Key_Schedule(key, key_len, 0, subkey);
	//block dec
	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 4; i++)
		{
			state[i] = 0;
			key_64[i] = 0;
		};
		input_1Block(state[0], state[1], state[2], state[3], in);
		sub = subkey + RC*32;
		//round function
		for (i = 0; i < RC; i++)
		{
			//for (j = 0; j < 4; j++)
				input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
				//key_64[j] = subkey[(50 - i) * 16 + j * 4 + 3] | (subkey[(50 - i) * 16 + j * 4 + 2] << 8) | (subkey[(50 - i) * 16 + j * 4 + 1] << 16) | (subkey[(50 - i) * 16 + j * 4 + 0] << 24);
			//key_64[j] = subkey[(RC-i) * 32 + j * 8 + 7] | (subkey[(RC - i) * 32 + j * 8 + 6] << 8) | (subkey[(RC - i) * 32 + j * 8 + 5] << 16) | (subkey[(RC - i) * 32 + j * 8 + 4] << 24) | ((uint64_t)subkey[(RC - i) * 32 + j * 8 + 3] << 32) | ((uint64_t)subkey[(RC - i) * 32 + j * 8 + 2] << 40) | ((uint64_t)subkey[(RC - i) * 32 + j * 8 + 1] << 48) | ((uint64_t)subkey[(RC - i) * 32 + j * 8 + 0] << 56);
			sub = sub - 32;
			AddRoundKey(state, key_64, state);
			
			invShiftRow(state, state_s);
			
			invSubcolumn(state_s, state);
		}
		//final add round 
		//for (j = 0; j < 4; j++)
			//key_64[j] = subkey[j * 4 + 3] | (subkey[j * 4 + 2] << 8) | (subkey[j * 4 + 1] << 16) | (subkey[j * 4 + 0] << 24);
		//key_64[j] = subkey[ j * 8 + 7] | (subkey[j * 8 + 6] << 8) | (subkey[ j * 8 + 5] << 16) | (subkey[ j * 8 + 4] << 24) | ((uint64_t)subkey[j * 8 + 3] << 32) | ((uint64_t)subkey[ j * 8 + 2] << 40) | ((uint64_t)subkey[ j * 8 + 1] << 48) | ((uint64_t)subkey[ j * 8] << 56);
			input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
			AddRoundKey(state, key_64, state);
		
			//trans state(64bit) to output(8bit)
			for (i = 0; i < 4; i++)
			{
				for (int j = 0; j < 8; j++) {
					output[16 * b + i * 8 + 7 - j] = (state[i] & (0xFF00000000000000 >> (j * 8))) >> ((7 - j) * 8);
				}
			}
	}
}
void TANGRAM_256_256_enc_Round(unsigned char *input, int in_len, unsigned char *output,  unsigned char *key, int key_len,int cryptoround) {
	uint64_t state[4], state_s[4], key_64[4];
	unsigned char subkey[32 * 83];
	int block_cnt = in_len / BLOCK_SIZE_256;
	int i, j;
	unsigned char *in = input; unsigned char *out = output;
	unsigned char *sub;

	//round number small than 44
	if (cryptoround > RC)
		return -1;
	//produce subkey
	Key_Schedule(key, key_len, 0, subkey);

	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 4; i++)
		{
			state[i] = 0;
			key_64[i] = 0;
		}
		//for (i = 0; i < 4; i++)
		//{
			input_1Block(state[0], state[1], state[2], state[3], in);
		//}
		
		//round function
			sub = subkey;
		for (i = 0; i < cryptoround; i++)
		{
			//for (j = 0; j < 4; j++)
				//key_64[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
				input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
			sub = sub + 32;
			AddRoundKey(state, key_64, state);
			
			SubCloumn(state, state_s);
			
			ShiftRow(state_s, state);
		
		}
		//final add round 
		//for (j = 0; j < 4; j++)
			//key_64[j] = subkey[cryptoround * 16 + j * 4 + 3] | (subkey[cryptoround * 16 + j * 4 + 2] << 8) | (subkey[cryptoround * 16 + j * 4 + 1] << 16) | (subkey[cryptoround * 16 + j * 4 + 0] << 24);
			input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
			AddRoundKey(state, key_64, state);
			//trans state(64bit) to output(8bit)
			for (i = 0; i < 4; i++)
			{
				for (int j = 0; j < 8; j++) {
					output[16 * b + i * 8 + 7 - j] = (state[i] & (0xFF00000000000000 >> (j * 8))) >> ((7 - j) * 8);
				}
			}
	}
}
void TANGRAM_256_256_enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len,unsigned char *iv) {
	//CBC
	uint64_t state[4], state_s[4], key_64[4];
	unsigned char subkey[32 * 83];
	int block_cnt = in_len / BLOCK_SIZE_256;
	int i, j;
	unsigned char *in = input; unsigned char *out = output;
	unsigned char *sub;
	for(i=0;i<4;i++)
		state[i] = 0;
	//xor iv
	for (i = 0; i < 32; i++)
		input[i] = input[i] ^ iv[i];
	unsigned char temp[32] = { 0x00 };
	//in first block,temp==iv
	//produce subkey
	Key_Schedule(key, key_len, 0, subkey);
	
	for (int b = 0; b < block_cnt; b++)
	{
		
		for (i = 0; i < 4; i++)
		{
			key_64[i] = 0;
		}
		for (i = 0; i < 32; i++)
			input[32 * b + i] ^= temp[i];
		/*for (i = 0; i < 4; i++)
		{
			state[i] = (input[16 * b + i * 4]^temp[i * 4]) | ((input[16 * b + i * 4 + 1]^temp[i*4+1]) << 8) | ((input[16 * b + i * 4 + 2]^temp[i*4+2]) << 16) | ((input[16 * b + i * 4 + 3]^temp[i*4+3]) << 24);
		}*/
		input_1Block(state[0], state[1], state[2], state[3], in);
		//round function
		sub = subkey;
		for (i = 0; i < RC; i++)
		{
			//for (j = 0; j < 4; j++)
				//key_64[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
				input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
				sub = sub + 32;
			AddRoundKey(state, key_64, state);
			
			SubCloumn(state, state_s);
			
			ShiftRow(state_s, state);
			
		}
		//final add round 
		//for (j = 0; j < 4; j++)
			//key_64[j] = subkey[50 * 16 + j * 4 + 3] | (subkey[50 * 16 + j * 4 + 2] << 8) | (subkey[50 * 16 + j * 4 + 1] << 16) | (subkey[50 * 16 + j * 4 + 0] << 24);
		input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
		AddRoundKey(state, key_64, state);
		//trans state(64bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 8; j++) {
				output[16 * b + i * 8 + 7 - j] = (state[i] & (0xFF00000000000000 >> (j * 8))) >> ((7 - j) * 8);
			}
		}
		//turn output to temp
		for (i = 0; i < 32; i++)
			temp[i] = output[16 * b + i];
	}
}
void TANGRAM_256_256_dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len,unsigned char *iv) {
	//CBC
	uint64_t state[4], state_s[4], key_64[4];
	unsigned char subkey[32 * 83];
	int block_cnt = in_len / BLOCK_SIZE_256;
	int i, j;
	unsigned char *in = input; unsigned char *out = output;
	unsigned char *sub;

	for (i = 0; i < 4; i++)
		state[i] = 0;
	//xor iv
	for (i = 0; i < 32; i++)
		input[i] = input[i] ^ iv[i];
	unsigned char temp[32] = { 0x00 };
	//in first block,temp==iv
	//produce subkey
	Key_Schedule(key, key_len, 0, subkey);
	
	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 32; i++)
			input[32 * b + i] ^= temp[i];
		for (i = 0; i < 4; i++)
		{
			key_64[i] = 0;
		}
		/*for (i = 0; i < 4; i++)
		{
			state[i] = (input[16 * b + i * 4] ^ temp[i * 4]) | ((input[16 * b + i * 4 + 1] ^ temp[i * 4 + 1]) << 8) | ((input[16 * b + i * 4 + 2] ^ temp[i * 4 + 2]) << 16) | ((input[16 * b + i * 4 + 3] ^ temp[i * 4 + 3]) << 24);
		}*/
		input_1Block(state[0], state[1], state[2], state[3], in);

		//round function
		sub = subkey + RC * 32;

		for (i = 0; i < RC; i++)
		{
			/*for (j = 0; j < 4; j++)
				key_64[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
			*/
			input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
			sub = sub - 32;
			AddRoundKey(state, key_64, state);
			
			invShiftRow(state, state_s);
			
			invSubcolumn(state_s, state);
			
		}
		//final add round 
		/*for (j = 0; j < 4; j++)
			key_64[j] = subkey[50 * 16 + j * 4 + 3] | (subkey[50 * 16 + j * 4 + 2] << 8) | (subkey[50 * 16 + j * 4 + 1] << 16) | (subkey[50 * 16 + j * 4 + 0] << 24);*/
		input_1Block(key_64[0], key_64[1], key_64[2], key_64[3], sub);
		
		AddRoundKey(state, key_64, state);
		
		//trans state(64bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 8; j++) {
				output[16 * b + i * 8 + 7 - j] = (state[i] & (0xFF00000000000000 >> (j * 8))) >> ((7 - j) * 8);
			}
		}
		//turn output to temp
		for (i = 0; i < 32; i++)
			temp[i] = output[16 * b + i];
	}
}