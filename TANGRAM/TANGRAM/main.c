#include "TANGRAM.h"
int main()
{
	unsigned char input[16] = { 0x7D, 0XAA, 0X65, 0X71,
		0X6F, 0X93, 0XC1, 0XDB,
		0x83, 0X9B, 0XF1, 0X24,
		0X6E, 0X93, 0X6D, 0XC7 };

	unsigned char output[16];
	unsigned char key[16] = { 0x50, 0x5C, 0x49, 0x90,
	0x02, 0xBF, 0x16, 0x25,
	0xFA, 0x55, 0x93, 0x12,
	0x96, 0x6E, 0x20, 0x88 };
	int j, in_len, out_len, key_len;
	in_len = 128;
	out_len = 128;
	key_len = 128;
	TANGRAM_128_128_enc(input, in_len, output, out_len, key, key_len);
	
		printf("plain:\n");
		for (j = 0; j < 16; j++)printf("%2x,", input[j]);
		printf("\n");
		printf("key:\n");
		for (j = 0; j < 16; j++)printf("%2x,", key[j]);
		printf("\n");
		printf("cipher\n");
		for (j = 0; j < 16; j++)printf("%2x,", output[j]);
		printf("\n");
	TANGRAM_128_128_dec(output, in_len,input, out_len,key, key_len);
		printf("plain:\n");
		for (j = 0; j < 16; j++)printf("%2x,", output[j]);
		printf("\n");
		printf("key:\n");
		for (j = 0; j < 16; j++)printf("%2x,", key[j]);
		printf("\n");
		printf("cipher\n");
		for (j = 0; j < 16; j++)printf("%2x,", input[j]);
		printf("\n");
		getchar();
}