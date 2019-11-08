#include "TANGRAM.h"
int main()
{
	//test vector
	unsigned char input[] = { 0x7D, 0XAA, 0X65, 0X71,
		0X6F, 0X93, 0XC1, 0XDB,
		0x83, 0X9B, 0XF1, 0X24,
		0X6E, 0X93, 0X6D, 0XC7,
		0X16, 0X51, 0Xf5, 0Xed,
		0X5e, 0X83, 0X7b, 0X5c,
		0Xa5, 0Xd7, 0X9e, 0Xbf,
		0Xa4, 0Xa5, 0X6f, 0Xce
	};

	unsigned char output[100] = {0x00};
	unsigned char key[16] = { 0x50, 0x5C, 0x49, 0x90,
	0x02, 0xBF, 0x16, 0x25,
	0xFA, 0x55, 0x93, 0x12,
	0x96, 0x6E, 0x20, 0x88 };
	int j, in_len,  key_len;
	int out_len;
	int CryptRound = 3;
	in_len = 128*2;
	//out_len = 128;
	key_len = 128;
	//encryption
	//TANGRAM_128_128_enc_Block(input, in_len, output, key, key_len);
	//decryption	
	//TANGRAM_128_128_dec_Block(output, in_len, input, out_len, key, key_len);

	//ECB模式加密
	Crypt_Enc_Block(input, in_len, output, &out_len, key, key_len);
	//ECB模式任意轮数加密
	Crypt_Enc_Block_Round(input,in_len,output,&out_len,key,key_len, CryptRound);
	//ECB模式解密
	Crypt_Dec_Block(input,in_len,output,&out_len,key,key_len);
	//CBC模式加密
	Crypt_Enc_Block_CBC(input, in_len, output, &out_len, key, key_len);
	//CBC模式解密
	Crypt_Dec_Block_CBC(input, in_len, output, &out_len, key, key_len);
	//测试输出
	/*printf("plain:\n");
	for (j = 0; j < 32; j++)printf("%2x,", input[j]);
	printf("\n");
	printf("key:\n");
	for (j = 0; j < 16; j++)printf("%2x,", key[j]);
	printf("\n");
	printf("cipher\n");
	for (j = 0; j < 32; j++)printf("%2x,", output[j]);
	printf("\n");*/
	
	getchar();
	
}