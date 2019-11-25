#include <stdint.h>
#include "TANGRAM.h"

int Crypt_Enc_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//ECB模式加密
{	
		TANGRAM_128_128_enc_Block(input, in_len, output, key, key_len);
	
		*out_len = in_len;
		return 0;
}
int Crypt_Dec_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//ECB模式解密
{
	TANGRAM_128_128_dec_Block(input, in_len, output, key, key_len);
	*out_len = in_len;
	return 0;
}
int Crypt_Enc_Block_Round(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len, int CryptRound)
{
	TANGRAM_128_128_enc_Round(input, in_len, output, key, key_len, CryptRound);
	*out_len = in_len;
	return 0;
}

int Crypt_Enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len) {
	unsigned char iv[16] = { 0x00 };
	
	TANGRAM_128_128_enc_Block_CBC(input, in_len, output, key, key_len, iv);
	*out_len = in_len;
	return 0;
}
int Crypt_Dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
{
	unsigned char iv[16] = { 0x00 };

	TANGRAM_128_128_dec_Block_CBC(input, in_len, output, key, key_len, iv);
	*out_len = in_len;
	return 0;
}
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
void invSubcolumn(uint32_t *a, uint32_t *b) {
	uint32_t t[13];
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

void ShiftRow(uint32_t *b, uint32_t *c) {
	c[0] = b[0];
	c[1] = _rotl(b[1], 1);
	c[2] = _rotl(b[2], 8);
	c[3] = _rotl(b[3], 11);
	
	//c[1] = (b[1] << 1) | ((b[1] & 0x80000000) >> 31);
	//c[2] = (b[2] << 8) | ((b[2] & 0xFF000000) >> 24);
	//c[3] = (b[3] << 11) | ((b[3] & 0xFFE00000) >> 21);
}

void invShiftRow(uint32_t *b, uint32_t *c) {
	c[0] = b[0];
	c[1] = _rotr(b[1], 1);
	c[1] = _rotr(b[2], 8);
	c[1] = _rotr(b[3], 11);
	//c[1] = (b[1] >> 1) | ((b[1] & 0x00000001) << 31);
	//c[2] = (b[2] >> 8) | ((b[2] & 0x000000FF) << 24);
	//c[3] = (b[3] >> 11) | ((b[3] & 0x000007FF) << 21);
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
		//for ( i = 0; i < 4; i++)
		//{
		//	row[i] = 0;
		//}
		//the first round subkey = seedkey
		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++)
			Subkey[i * 4 + j] = Seedkey[i * 4 + 3-j];
		//
		////8bit to 32bit
		//for ( i = 0; i < 4; i++)
		//{
		//	row[i] = row[i] | Seedkey[i * 4 ] | (Seedkey[i * 4 + 1] << 8) | (Seedkey[i * 4 + 2] << 16) | (Seedkey[i * 4 + 3] << 24);
		//	
		//}
		//input_1Block(Subkey[0], Subkey[1], Subkey[2], Subkey[3], Seedkey);
		input_1Block(row[0], row[1], row[2], row[3], Seedkey);
		for ( r = 0; r < 44; r++)
		{
			//SubCloumn
			SubCloumn(row, row_1);
			//Feistel
			row_2[3] = row_1[0];
			//row_2[0] = ((row_1[0] << 7) | (row_1[0] & 0xFE000000) >> 25) ^ row_1[1];
			row_2[0] = _rotl(row_1[0], 7)^row_1[1];
			row_2[1] = row_1[2];
			row_2[2] = _rotl(row_1[2], 17) ^ row_1[3];
			//row_2[2] = ((row_1[2] << 17) | (row_1[2] & 0xFFFF8000) >> 15) ^ row_1[3];
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

void TANGRAM_128_128_enc_Block(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len) {
	//ECB
	uint32_t state[4],state_s[4],key_32[4];
	unsigned char subkey[16 * 45];
	int block_cnt = in_len / BLOCK_SIZE;
	int i, j;
	//produce subkey
	Key_Schedule(key, 128, 0, subkey);
	//block enc
	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 4; i++)
		{
			state[i] = 0;
			key_32[i] = 0;
		}
		for (i = 0; i < 4; i++)//state origin
		{
			state[i] = input[16 * b + i * 4] | (input[16 * b + i * 4 + 1] << 8) | (input[16 * b + i * 4 + 2] << 16) | (input[16 * b + i * 4 + 3] << 24);
		}
		
		//round function
		for (i = 0; i < 44; i++)
		{
			for (j = 0; j < 4; j++)
				key_32[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
			
			AddRoundKey(state, key_32, state);

			SubCloumn(state, state_s);

			ShiftRow(state_s, state);
			
		}
		//final add round 
		for (j = 0; j < 4; j++)
			key_32[j] = subkey[44 * 16 + j * 4 + 3] | (subkey[44 * 16 + j * 4 + 2] << 8) | (subkey[44 * 16 + j * 4 + 1] << 16) | (subkey[44 * 16 + j * 4 + 0] << 24);
		AddRoundKey(state, key_32, state);
		//trans state(32bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++) {
				output[16 * b + i * 4 + 3 - j] = (state[i] & (0xFF000000 >> (j * 8))) >> ((3 - j) * 8);
			}

		}
	}
}

void TANGRAM_128_128_dec_Block(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len) {
	//ECB
	uint32_t state[4], state_s[4], key_32[4];
	unsigned char subkey[16 * 45];
	int i, j;
	int block_cnt = in_len / BLOCK_SIZE;
	//produce subkey
	Key_Schedule(key, 128, 0, subkey);
	//block dec
	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 4; i++)
		{
			state[i] = 0;
			key_32[i] = 0;
		}
		for (i = 0; i < 4; i++)
		{
			state[i] = input[16 * b + i * 4] | (input[16 * b + i * 4 + 1] << 8) | (input[16 * b + i * 4 + 2] << 16) | (input[16 * b + i * 4 + 3] << 24);
		}

		//round function
		for (i = 0; i < 44; i++)
		{
			for (j = 0; j < 4; j++)
				key_32[j] = subkey[(44 - i) * 16 + j * 4 + 3] | (subkey[(44 - i) * 16 + j * 4 + 2] << 8) | (subkey[(44 - i) * 16 + j * 4 + 1] << 16) | (subkey[(44 - i) * 16 + j * 4 + 0] << 24);
			
			AddRoundKey(state, key_32, state);
			
			invShiftRow(state, state_s);
			
			invSubcolumn(state_s, state);
		}
		//final add round 
		for (j = 0; j < 4; j++)
			key_32[j] = subkey[j * 4 + 3] | (subkey[j * 4 + 2] << 8) | (subkey[j * 4 + 1] << 16) | (subkey[j * 4 + 0] << 24);
		
		AddRoundKey(state, key_32, state);
		
		//trans state(32bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++) {
				output[16 * b + i * 4 + 3 - j] = (state[i] & (0xFF000000 >> (j * 8))) >> ((3 - j) * 8);
			}

		}
	}
}
void TANGRAM_128_128_enc_Round(unsigned char *input, int in_len, unsigned char *output,  unsigned char *key, int key_len,int cryptoround) {
	uint32_t state[4], state_s[4], key_32[4];
	unsigned char subkey[16 * 45];
	int i, j;
	int block_cnt = in_len / BLOCK_SIZE;
	//round number small than 44
	if (cryptoround > 44)
		return -1;
	//produce subkey
	Key_Schedule(key, 128, 0, subkey);

	for (int b = 0; b < block_cnt; b++)
	{
		for (i = 0; i < 4; i++)
		{
			state[i] = 0;
			key_32[i] = 0;
		}
		for (i = 0; i < 4; i++)
		{
			state[i] = input[16 * b + i * 4] | (input[16 * b + i * 4 + 1] << 8) | (input[16 * b + i * 4 + 2] << 16) | (input[16 * b + i * 4 + 3] << 24);
		}
		
		//round function
		for (i = 0; i < cryptoround; i++)
		{
			for (j = 0; j < 4; j++)
				key_32[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
			
			AddRoundKey(state, key_32, state);
			
			SubCloumn(state, state_s);
			
			ShiftRow(state_s, state);
		
		}
		//final add round 
		for (j = 0; j < 4; j++)
			key_32[j] = subkey[cryptoround * 16 + j * 4 + 3] | (subkey[cryptoround * 16 + j * 4 + 2] << 8) | (subkey[cryptoround * 16 + j * 4 + 1] << 16) | (subkey[cryptoround * 16 + j * 4 + 0] << 24);
		AddRoundKey(state, key_32, state);
		//trans state(32bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++) {
				output[16 * b + i * 4 + 3 - j] = (state[i] & (0xFF000000 >> (j * 8))) >> ((3 - j) * 8);
			}

		}
	}
}
void TANGRAM_128_128_enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len,unsigned char *iv) {
	//CBC
	uint32_t state[4], state_s[4], key_32[4];
	unsigned char subkey[16 * 45];
	unsigned char *sub;
	
	int block_cnt = in_len / BLOCK_SIZE;
	int i, j;
	//for(i=0;i<4;i++)
		//state[i] = 0;
	//xor iv
	/*for (i = 0; i < 16; i++)
		input[i] = input[i] ^ iv[i];*/
	unsigned char temp[16] = { 0x00 };
	//in first block,temp==iv
	//produce subkey
	Key_Schedule(key, 128, 0, subkey);
	
	for (int b = 0; b < block_cnt; b++)
	{
		sub = subkey;
		/*for (i = 0; i < 4; i++)
		{
			key_32[i] = 0;
		}*/
		//for (i = 0; i < 4; i++)
		//{
			//state[i] = (input[16 * b + i * 4]^temp[i * 4]) | ((input[16 * b + i * 4 + 1]^temp[i*4+1]) << 8) | ((input[16 * b + i * 4 + 2]^temp[i*4+2]) << 16) | ((input[16 * b + i * 4 + 3]^temp[i*4+3]) << 24);
		//}
		input_1Block_CBC(state[0], state[1], state[2], state[3],input,temp);
		//round function
		for (i = 0; i < RC; i++)
		{
			//for (j = 0; j < 4; j++)
				//key_32[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);
			input_1Block(key_32[0], key_32[1], key_32[2], key_32[3], sub);
			sub = sub + 16;
			AddRoundKey(state, key_32, state);
			
			SubCloumn(state, state_s);
			
			ShiftRow(state_s, state);
			
		}
		//final add round 
		//for (j = 0; j < 4; j++)
			//key_32[j] = subkey[44 * 16 + j * 4 + 3] | (subkey[44 * 16 + j * 4 + 2] << 8) | (subkey[44 * 16 + j * 4 + 1] << 16) | (subkey[44 * 16 + j * 4 + 0] << 24);
		input_1Block(key_32[0], key_32[1], key_32[2], key_32[3], sub);
		AddRoundKey(state, key_32, state);
		//trans state(32bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++) {
				output[16 * b + i * 4 + 3 - j] = (state[i] & (0xFF000000 >> (j * 8))) >> ((3 - j) * 8);
			}
		}
		//turn output to temp
		for (i = 0; i < 16; i++)
			temp[i] = output[16 * b + i];
	}
}
void TANGRAM_128_128_dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len,unsigned char *iv) {
	//CBC
	uint32_t state[4], state_s[4], key_32[4];
	unsigned char subkey[16 * 45];
	unsigned char *sub;
	int block_cnt = in_len / BLOCK_SIZE;
	int i, j;
	for (i = 0; i < 4; i++)
		state[i] = 0;
	//xor iv
	for (i = 0; i < 16; i++)
		input[i] = input[i] ^ iv[i];
	unsigned char temp[16] = { 0x00 };
	//in first block,temp==iv
	//produce subkey
	Key_Schedule(key, 128, 0, subkey);
	
	for (int b = 0; b < block_cnt; b++)
	{
		sub = subkey + 16*RC;
		/*for (i = 0; i < 4; i++)
		{
			key_32[i] = 0;
		}
		for (i = 0; i < 4; i++)
		{
			state[i] = (input[16 * b + i * 4] ^ temp[i * 4]) | ((input[16 * b + i * 4 + 1] ^ temp[i * 4 + 1]) << 8) | ((input[16 * b + i * 4 + 2] ^ temp[i * 4 + 2]) << 16) | ((input[16 * b + i * 4 + 3] ^ temp[i * 4 + 3]) << 24);
		}*/
		input_1Block_CBC(state[0], state[1], state[2], state[3], input, temp);
		

		//round function
		for (i = 0; i < 44; i++)
		{
			/*for (j = 0; j < 4; j++)
				key_32[j] = subkey[i * 16 + j * 4 + 3] | (subkey[i * 16 + j * 4 + 2] << 8) | (subkey[i * 16 + j * 4 + 1] << 16) | (subkey[i * 16 + j * 4 + 0] << 24);*/
			input_1Block(key_32[0], key_32[1], key_32[2], key_32[3], sub);
			sub = sub - 16;
			AddRoundKey(state, key_32, state);
			
			invShiftRow(state, state_s);
			
			invSubcolumn(state_s, state);
			
		}
		//final add round 
		/*for (j = 0; j < 4; j++)
			key_32[j] = subkey[j * 4 + 3] | (subkey[j * 4 + 2] << 8) | (subkey[j * 4 + 1] << 16) | (subkey[j * 4 + 0] << 24);
		*/
		input_1Block(key_32[0], key_32[1], key_32[2], key_32[3], sub);
		AddRoundKey(state, key_32, state);
		
		//trans state(32bit) to output(8bit)
		for (i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++) {
				output[16 * b + i * 4 + 3 - j] = (state[i] & (0xFF000000 >> (j * 8))) >> ((3 - j) * 8);
			}
		}
		//turn output to temp
		for (i = 0; i < 16; i++)
			temp[i] = output[16 * b + i];
	}
}