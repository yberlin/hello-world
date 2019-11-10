#include "TANGRAM.h"
int main()
{
	//test input
	unsigned char key[32] = { 0x70, 0xC9, 0X26, 0x69,
	0x65, 0x99, 0x48, 0x79,
	0xE3, 0xC4, 0x53, 0x3F,
	0x11, 0xC3, 0xCA, 0x2C,
	0x63, 0xD1, 0x96, 0x62,
	0x83, 0xB6, 0xE9, 0xEA,
	0x72, 0x14, 0xC4, 0xFE,
	0xC1, 0xC1, 0x8A, 0x08};
	unsigned char input[] = { 0xED, 0X57, 0XDC, 0X2B,
		0X47, 0X7D, 0X79, 0X13,
		0x56, 0XA8, 0X94, 0X72,
		0X48, 0X41, 0X0E, 0X5E,
		0XBC, 0X44, 0X4A, 0XFC,
		0XAE, 0XF4, 0X95, 0X0D,
		0X40, 0X1D, 0XA4, 0X6B,
		0X34, 0XE7, 0X65, 0X2B
	};

	unsigned char output[100] = {0x00};
	
	int j, in_len,  key_len;
	int out_len;
	int CryptRound = 3;
	in_len = 256;
	//out_len = 128;
	key_len = 256;
	//encryption
	//TANGRAM_128_128_enc_Block(input, in_len, output, key, key_len);
	//decryption	
	//TANGRAM_128_128_dec_Block(output, in_len, input, out_len, key, key_len);

	//ECB模式加密
	Crypt_Enc_Block(input, in_len, output, &out_len, key, key_len);
	//ECB模式任意轮数加密
	//Crypt_Enc_Block_Round(input,in_len,output,&out_len,key,key_len, CryptRound);
	//ECB模式解密
	//Crypt_Dec_Block(input,in_len,output,&out_len,key,key_len);
	//CBC模式加密
	//Crypt_Enc_Block_CBC(input, in_len, output, &out_len, key, key_len);
	//CBC模式解密
	//Crypt_Dec_Block_CBC(input, in_len, output, &out_len, key, key_len);
	//测试输出
	/*printf("plain:\n");
	for (j = 0; j < 32; j++)printf("%2x,", input[j]);
	printf("\n");
	printf("key:\n");
	for (j = 0; j < 32; j++)printf("%2x,", key[j]);
	printf("\n");
	printf("cipher\n");
	for (j = 0; j < 32; j++)printf("%2x,", output[j]);
	printf("\n");*/
	
	getchar();
	
}