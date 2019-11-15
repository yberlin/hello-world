#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define BLOCK_SIZE 128
#define RC 44
void Key_Schedule(unsigned char *Seedkey, int Keylen, unsigned char Direction, unsigned char *Subkey);
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
/** @brief 将变量  @a x 的第 @a n 个32-比特字取出 */
#  define word32_in(x,n)    (*((uint32_t*)(x)+(n)))
/** @brief 从 @a ip 地址开始，将一个分组的第0、1、2、3个32-比特字依次装载到 @a x0, @a x1, @a x2, @a x3 中。
 *
 *  @param [ in] ip 一个16-字节分组在内存中的输入起始地址
 *  @param [out] x0 存放TANGRAM状态矩阵的第 0 行的寄存器
 *  @param [out] x1 存放TANGRAM状态矩阵的第 1 行的寄存器
 *  @param [out] x2 存放TANGRAM状态矩阵的第 2 行的寄存器
 *  @param [out] x3 存放TANGRAM状态矩阵的第 3 行的寄存器
 */
#define input_1Block(x0, x1, x2, x3, ip)                                                                                      \
{                                                                                                                             \
	x0 = word32_in(ip, 0);                                                                                                    \
	x1 = word32_in(ip, 1);                                                                                                    \
	x2 = word32_in(ip, 2);                                                                                                    \
	x3 = word32_in(ip, 3);                                                                                                    \
}
#define input_1Block_CBC(x0, x1, x2, x3, ip, pre)                                                                              \
{                                                                                                                             \
	x0 = word32_in(ip, 0)^word32_in(pre, 0);                                                                                   \
	x1 = word32_in(ip, 1)^word32_in(pre, 1);                                                                                   \
	x2 = word32_in(ip, 2)^word32_in(pre, 2);                                                                                   \
	x3 = word32_in(ip, 3)^word32_in(pre, 3);                                                                                   \
}
void TANGRAM_128_128_enc_Block(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len);
void TANGRAM_128_128_dec_Block(unsigned char *input, int in_len, unsigned char *output,  unsigned char *key, int key_len);
void TANGRAM_128_128_enc_Round(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len, int cryptoround);
void TANGRAM_128_128_enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len, unsigned char *iv);
void TANGRAM_128_128_dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, unsigned char *key, int key_len, unsigned char *iv);
int Crypt_Enc_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len);
int Crypt_Enc_Block_Round(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len, int CryptRound);
int Crypt_Dec_Block(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len);
int Crypt_Enc_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len);
int Crypt_Dec_Block_CBC(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int key_len);