#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int Crypt_Enc_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//ECB模式加密
{
	// input    明文
	// in_len   明文比特长度
	// output   密文
	// out_len  密文比特长度
	// key      密钥
	// key_len  密钥比特长度
}

int Crypt_Dec_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//ECB模式解密
{
	// input    密文
	// in_len   密文比特长度
	// output   明文
	// out_len  明文比特长度
	// key      密钥
	// key_len  密钥比特长度
}

int Crypt_Enc_Block_Round(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len, int CryptRound)
//ECB模式任意轮数加密
{
	//函数执行第1轮至第CryptRound轮加密，输出第CryptRound轮结果
	// input    明文
	// in_len   明文比特长度
	// output   密文
	// out_len  密文比特长度
	// key      密钥
	// key_len  密钥比特长度
}

int Crypt_Enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//CBC模式加密
{
	// input    明文
	// in_len   明文比特长度
	// output   密文
	// out_len  密文比特长度
	// key      密钥
	// key_len  密钥比特长度
}

int Crypt_Dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len)
//CBC模式解密
{
	// input    密文
	// in_len   密文比特长度
	// output   明文
	// out_len  明文比特长度
	// key      密钥
	// key_len  密钥比特长度
}

void Key_Schedule(unsigned char *Seedkey, int Keylen, unsigned char Direction, unsigned char *Subkey)
//根据初始密钥产生各轮子密钥
{
	//Seedkey     密钥
	//Keylen      密钥比特长度
	//Direction:  0 加密，1 解密
	//Subkey      子密钥
}
static unsigned char SBOX[] = {
0x8,0x0,0x3,0xe,0x7,0xd,0xc,0x2,0x6,0xf,0x5,0x9,0xa,0x1,0xb,0x4
};
static unsigned char INVSBOX[] = {
0x1,0xd,0x7,0x2,0xf,0xa,0x8,0x4,0x0,0xb,0xc,0xe,0x6,0x5,0x3,0x9
};
static unsigned char RC44[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06, 0x0C, 0x18, 0x31, 
	0x22, 0x05, 0x0A, 0x14, 0x29, 0x13, 0x27, 0x0F, 0x1E, 0x3D, 0x3A, 
	0x34, 0x28, 0x11, 0x23, 0x07, 0x0E, 0x1C, 0x39, 0x32, 0x24, 0x09, 
	0x12, 0x25, 0x0B, 0x16, 0x2D, 0x1B, 0x37, 0x2E, 0x1D, 0x3B, 0x36
};

static unsigned char RC49[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 
	0x06, 0x0C, 0x18, 0x31, 0x22, 0x05, 0x0A, 
	0x14, 0x29, 0x13, 0x27, 0x0F, 0x1E, 0x3D, 
	0x3A, 0x34, 0x28, 0x11, 0x23, 0x07, 0x0E, 
	0x1C, 0x39, 0x32, 0x24, 0x09, 0x12, 0x25, 
	0x0B, 0x16, 0x2D, 0x1B, 0x37, 0x2E, 0x1D, 
	0x3B, 0x36, 0x2C, 0x19, 0x33, 0x26, 0x0D 
};

static unsigned char RC82[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x61,
	0x42, 0x05, 0x0A, 0x14, 0x28, 0x51, 0x23, 0x47, 0x0F, 0x1E, 0x3C, 0x79, 0x72,
	0x64, 0x48, 0x11, 0x22, 0x45, 0x0B, 0x16, 0x2C, 0x59, 0x33, 0x67, 0x4E, 0x1D,
	0x3A, 0x75, 0x6A, 0x54, 0x29, 0x53, 0x27, 0x4F, 0x1F, 0x3E, 0x7D, 0x7A, 0x74,
	0x68, 0x50, 0x21, 0x43, 0x07, 0x0E, 0x1C, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12,
	0x24, 0x49, 0x13, 0x26, 0x4D, 0x1B, 0x36, 0x6D, 0x5A, 0x35, 0x6B, 0x56, 0x2D,
	0x5B, 0x37, 0x6F, 0x5E}; 