#include "TANGRAM.h"
int main()
{
	unsigned char input[16] = { 0xB8, 0X2F, 0X4B, 0XF8,
		0XF1, 0X04, 0X37, 0XF8,
		0x1B, 0X23, 0X29, 0XE8,
		0X4B, 0X8A, 0XC5, 0X3F };

	unsigned char output[16];
	unsigned char key[16] = { 0x50, 0x5C, 0x49, 0x90,
	0x02, 0xBF, 0x16, 0x25,
	0xFA, 0x55, 0x93, 0x12,
	0x96, 0x6E, 0x20, 0x88 };
	int j, in_len, out_len, key_len;
	in_len = 128;
	out_len = 128;
	key_len = 128;
	TANGRAM_128_128(input, in_len, output, out_len, key, key_len);
	

}