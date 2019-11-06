#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
//void Key_Schedule(unsigned char *Seedkey, int Keylen, unsigned char Direction, unsigned char *Subkey) {
	//Seedkey     密钥
	//Keylen      密钥比特长度
	//Direction:  0 加密，1 解密
	//Subkey      子密钥
	static unsigned char RC44[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06, 0x0C, 0x18, 0x31, 
	0x22, 0x05, 0x0A, 0x14, 0x29, 0x13, 0x27, 0x0F, 0x1E, 0x3D, 0x3A, 
	0x34, 0x28, 0x11, 0x23, 0x07, 0x0E, 0x1C, 0x39, 0x32, 0x24, 0x09, 
	0x12, 0x25, 0x0B, 0x16, 0x2D, 0x1B, 0x37, 0x2E, 0x1D, 0x3B, 0x36
};
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
};

int main(){
	unsigned char Seedkey[]= {0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01 };;
	int Keylen;
	unsigned char Direction;
	unsigned char Subkey[16*45];
	
	Keylen=128;
	int i, r;
	uint32_t row[4], row_1[4],row_2[4];
	if (Keylen == 128)
	{
		for ( i = 0; i < 4; i++)
		{
			row[i] = 0;
		}
		//the first round subkey = seedkey
		for (i = 0; i < 16; i++)
			Subkey[i] = Seedkey[i];
		//8bit to 32bit
		for ( i = 0; i < 4; i++)
		{
			row[i] = row[i] | Seedkey[i * 4 + 3] | (Seedkey[i * 4 + 2] << 8) | (Seedkey[i * 4 + 1] << 16) | (Seedkey[i * 4 + 0] << 24);
		}
		for ( r = 0; r < 44; r++)
		{
			//SubCloumn
			SubCloumn(row, row_1);
			//Feistel
			row_2[3] = row_1[0];
			row_2[0] = ((row_1[0] << 7) | (row_1[0] & 0xFE000000) >> 25) ^ row_1[1];
			row_2[1] = row_1[2];
			row_2[2] = ((row_1[2] << 17) | (row_1[2] & 0xFFFF8000 )>> 15) ^ row_1[3];
			//round constant
			row_2[0] = row_2[0] ^ RC44[r];
			//128 key schedule
			//Subkey[0]--Subkey[3]->row_2[0]
			//Subkey[4]--Subkey[7]->row_2[1]
			for (i = 0; i < 4; i++)
			{	
				for (int j = 0; j < 4; j++) {
					Subkey[16 * (r + 1) + i + j] = (row_2[i] & (0xFF000000 >> (j * 8))) >> ((3-j) * 8);
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
	printf("subkey:\n");
	for ( i = 0; i < 45; i++)
	{
		printf("round:%d\n", i);
		for (int j = 0; j < 4; j++)
		{
			for (int n = 0; n < 4; n++)
			{
				printf("%2x ", Subkey[i*16 + j*4 + n]);
			}
			printf("\n");
		}
	}	
}
