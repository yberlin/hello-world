#include "TANGRAM.h"
#include "stdio.h"
#include "stdint.h"
#include "stdlib.h"

#include <windows.h>


//测试加解密256byte的数据量所用的cycle数
uint64_t test_cycle()
{
	uint64_t start, end, result = 0;
	uint8_t pa[16 * 16] = { 0 };  //256byte
	uint8_t ca[16 * 16] = { 0 };
	uint8_t key[16] = { 0 };
	int out_len;

	for (int i = 0; i < 16; i++)
	{
		key[i] = rand() % 256;
	}
	for (int i = 0; i < 16 * 16; i++)
	{
		pa[i] = rand() % 256;
	}

	start = __rdtsc();
	//Crypt_Enc_Block_CBC(pa, 16 * 16, ca, &out_len, key, 256);
	Crypt_Dec_Block_CBC(pa, 16 * 16, ca, &out_len, key, 256);
	end = __rdtsc();
	result = end - start;

	return result;
}

//测试加解密256byte的数据量所用的时间
double test_sec()
{
	uint8_t pa[16 * 16] = { 0 };
	uint8_t ca[16 * 16] = { 0 };
	uint8_t key[16] = { 0 };
	int out_len;

	for (int i = 0; i < 16; i++)
	{
		key[i] = rand() % 256;
	}
	for (int i = 0; i < 16 * 16; i++)
	{
		pa[i] = rand() % 256;
	}

	LARGE_INTEGER nFreq;
	LARGE_INTEGER nBeginTime;
	LARGE_INTEGER nEndTime;
	double time = 0;
	if (!QueryPerformanceFrequency(&nFreq))
	{
		printf("QueryPerformanceFrequency not supported!!!");
		return;
	}

	QueryPerformanceCounter(&nBeginTime);
	//Crypt_Enc_Block_CBC(pa, 16 * 16, ca, &out_len, key, 256);
	Crypt_Dec_Block_CBC(pa, 16 * 16, ca, &out_len, key, 256);
	QueryPerformanceCounter(&nEndTime);
	time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;  //单位s

	return time;
}

int main()
{
	//test input
	//unsigned char key[32] = { 0x70, 0xC9, 0X26, 0x69,
	//0x65, 0x99, 0x48, 0x79,
	//0xE3, 0xC4, 0x53, 0x3F,
	//0x11, 0xC3, 0xCA, 0x2C,
	//0x63, 0xD1, 0x96, 0x62,
	//0x83, 0xB6, 0xE9, 0xEA,
	//0x72, 0x14, 0xC4, 0xFE,
	//0xC1, 0xC1, 0x8A, 0x08};
	//unsigned char input[] = { 0xED, 0X57, 0XDC, 0X2B,
	//	0X47, 0X7D, 0X79, 0X13,
	//	0x56, 0XA8, 0X94, 0X72,
	//	0X48, 0X41, 0X0E, 0X5E,
	//	0XBC, 0X44, 0X4A, 0XFC,
	//	0XAE, 0XF4, 0X95, 0X0D,
	//	0X40, 0X1D, 0XA4, 0X6B,
	//	0X34, 0XE7, 0X65, 0X2B
	//};

	//unsigned char output[100] = {0x00};
	//
	//int j, in_len,  key_len;
	//int out_len;
	//int CryptRound = 3;
	//in_len = 256;
	////out_len = 128;
	//key_len = 256;
	//encryption
	//TANGRAM_128_128_enc_Block(input, in_len, output, key, key_len);
	//decryption	
	//TANGRAM_128_128_dec_Block(output, in_len, input, out_len, key, key_len);

	//ECB模式加密
	//Crypt_Enc_Block(input, in_len, output, &out_len, key, key_len);
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
	//速度: cycles/byte

	uint64_t sum = 0;
	double cpb = 0.0;

	for (int i = 0; i < 100000; i++)
	{
		sum += test_cycle();
	}
	cpb = (double)sum / ((double)(16) * 16 * 100000);
	//printf("加密1byte数据所需的cycle数为：%lf\n", cpb);
	printf("解密1byte数据所需的cycle数为：%lf\n", cpb);

	//速度: Mbit/s

	double sum_mbit = 0.0;
	double mbps = 0.0;

	for (int i = 0; i < 100000; i++)
	{
		sum_mbit += test_sec();
	}
	mbps = ((double)(16) * 16 * 8 * 100000 / 1000000) / (double)sum_mbit;
	//printf("1秒加密%lf Mbit\n", mbps);
	printf("1秒解密%lf Mbit\n", mbps);
	getchar();
	
}