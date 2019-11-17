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
	////test vector
	//unsigned char input[] = { 0xA6, 0X75, 0X2B, 0XBE,
	//	0X3D, 0X42, 0XBA, 0X84,
	//	0x60, 0X81, 0X12, 0X3E,
	//	0X31, 0XC0, 0X76, 0XEB,
	//	0XD8, 0X98, 0X27, 0X2E,
	//	0X49, 0X08, 0X50, 0XC2,
	//	0XCB, 0XB6, 0XCE, 0XD9,
	//	0XB6, 0Xa3, 0XEA, 0X6e
	//};

	//unsigned char output[100] = {0x00};
	//unsigned char key[32] = { 0x9A, 0xE6, 0x89, 0xF5,
	//0x5E, 0x67, 0x87, 0xEE,
	//0xB6, 0x40, 0x93, 0xF0,
	//0x44, 0x19, 0xE0, 0xEB,
	//0x06, 0x8F, 0x4B, 0x93,
	//0xD0, 0x5C, 0xA3, 0x63,
	//0x48, 0x08, 0xFE, 0x59,
	//0xFE, 0x5F, 0xD2, 0x98};
	//int j, in_len,  key_len;
	//int out_len;
	//int CryptRound = 3;
	//in_len = 128*2;
	////out_len = 128;
	//key_len = 128*2;
	////encryption
	////TANGRAM_128_128_enc_Block(input, in_len, output, key, key_len);
	////decryption	
	////TANGRAM_128_128_dec_Block(output, in_len, input, out_len, key, key_len);

	////ECB模式加密
	//Crypt_Enc_Block(input, in_len, output, &out_len, key, key_len);
	////ECB模式任意轮数加密
	////Crypt_Enc_Block_Round(input,in_len,output,&out_len,key,key_len, CryptRound);
	////ECB模式解密
	////Crypt_Dec_Block(input,in_len,output,&out_len,key,key_len);
	////CBC模式加密
	////Crypt_Enc_Block_CBC(input, in_len, output, &out_len, key, key_len);
	////CBC模式解密
	////Crypt_Dec_Block_CBC(input, in_len, output, &out_len, key, key_len);
	////测试输出
	//printf("plain:\n");
	//for (j = 0; j < 32; j++)printf("%2x,", input[j]);
	//printf("\n");
	//printf("key:\n");
	//for (j = 0; j < 32; j++)printf("%2x,", key[j]);
	//printf("\n");
	//printf("cipher\n");
	//for (j = 0; j < 32; j++)printf("%2x,", output[j]);
	//printf("\n");

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