#include "TANGRAM.h"
int main()
{
	unsigned char input[16] = {0x01,0x01, 0x01, 0x01, 
	0x01, 0x01, 0x01, 0x01, 
	0x01, 0x01, 0x01, 0x01, 
	0x01, 0x01, 0x01, 0x01 };

	unsigned char output[16];
	unsigned char key[16] = { 0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01 };
	int j, in_len, out_len, key_len;
	in_len = 128;
	out_len = 128;
	key_len = 128;
	TANGRAM_128_128(input, in_len, output, out_len, key, key_len);
	
		printf("plain:\n");
		for (j = 0; j < 16; j++)printf("%2x,", input[j]);
		printf("\n");
		printf("key:\n");
		for (j = 0; j < 16; j++)printf("%2x,", key[j]);
		printf("\n");
		printf("cipher\n");
		for (j = 0; j < 16; j++)printf("%2x,", output[j]);
		printf("\n");
		getchar();
}