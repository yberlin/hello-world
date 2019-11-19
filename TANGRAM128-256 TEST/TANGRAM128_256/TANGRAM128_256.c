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
	//test vector
	unsigned char input[] = { 0x66, 0X67, 0X0A, 0XDF,
		0X6B, 0X43, 0X02, 0X15,
		0xD6, 0X6F, 0X8C, 0X3F,
		0X64, 0X89, 0X3D, 0XA3,
		0XF7, 0X65, 0X19, 0XFA,
		0XEC, 0X8C, 0XE7, 0XD0,
		0XC1, 0XAD, 0XD5, 0X30,
		0X04, 0X39, 0X4E, 0XD1
	};

	unsigned char output[100] = {0x00};
	unsigned char key[32] = { 0x70, 0x2E, 0x65, 0x4F,
	0xCF, 0x2D, 0x35, 0xD0,
	0x71, 0xF7, 0xD8, 0x9D,
	0xE4, 0x45, 0x1B, 0x87,
	0x36, 0x73, 0x51, 0xBF,
	0x12, 0xD8, 0x3B, 0x4E,
	0x44, 0x91, 0x5F, 0xA8,
	0x98, 0x38, 0x0D, 0xEA};
	int j, in_len,  key_len;
	int out_len;
	int CryptRound = 3;
	in_len = 128*2;
	//out_len = 128;
	key_len = 128*2;
	//encryption
	//TANGRAM_128_128_enc_Block(input, in_len, output, key, key_len);
	//decryption	
	//TANGRAM_128_128_dec_Block(output, in_len, input, out_len, key, key_len);

	//ECB模式加密
	Crypt_Enc_Block(input, in_len, output, &out_len, key, key_len);
	//测试输出
	printf("plain:\n");
	for (j = 0; j < 32; j++)printf("%2x,", input[j]);
	printf("\n");
	printf("key:\n");
	for (j = 0; j < 32; j++)printf("%2x,", key[j]);
	printf("\n");
	printf("cipher\n");
	for (j = 0; j < 32; j++)printf("%2x,", output[j]);
	printf("\n");
	//ECB模式任意轮数加密
	//Crypt_Enc_Block_Round(input,in_len,output,&out_len,key,key_len, CryptRound);
	//ECB模式解密
	Crypt_Dec_Block(output,in_len,input,&out_len,key,key_len);
	//CBC模式加密
	//Crypt_Enc_Block_CBC(input, in_len, output, &out_len, key, key_len);
	printf("plain:\n");
	for (j = 0; j < 32; j++)printf("%2x,", output[j]);
	printf("\n");
	printf("key:\n");
	for (j = 0; j < 32; j++)printf("%2x,", key[j]);
	printf("\n");
	printf("cipher\n");
	for (j = 0; j < 32; j++)printf("%2x,", input[j]);
	printf("\n");
	//CBC模式解密
	//Crypt_Dec_Block_CBC(output, in_len, input, &out_len, key, key_len);
	//测试输出
	

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