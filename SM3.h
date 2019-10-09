#pragma once

typedef struct _MsgInt {
	unsigned int* msgInt;//原始消息字符转化为int指针数组，每4个字符转化为一个int个数
	int intCount;//int数个数
}MsgInt;

typedef struct _ExtendMsgInt {
	unsigned int W[68];
	unsigned int W1[64];
}ExtendMsgInt;

// 初始向量
const unsigned int IV[8] = {
	0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
	0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

/*
 * 宏函数NOT_BIG_ENDIAN()
 * 用于测试运行环境是否为大端，小端返回true
 */
static const int endianTestNum = 1;
#define NOT_BIG_ENDIAN() ( *(char *)&endianTestNum == 1 )

#define FF_LOW(x,y,z) ( (x) ^ (y) ^ (z))
#define FF_HIGH(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG_LOW(x,y,z) ( (x) ^ (y) ^ (z))
#define GG_HIGH(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

//#define ROTATE_LEFT(uint32,shift) ( (uint32) = ( ( (uint32) << (shift) ) | ( (uint32) >> (32 - (shift)) ) ) )
// 上面写的会改变传入的参数的值，影响MsgExtend函数里W 的运算
#define ROTATE_LEFT(uint32,shift) ( ( ( (uint32) << (shift) ) | ( (uint32) >> (32 - (shift)) ) ) )

#define P0(x) ((x) ^  ROTATE_LEFT((x),9) ^ ROTATE_LEFT((x),17))
#define P1(x) ((x) ^  ROTATE_LEFT((x),15) ^ ROTATE_LEFT((x),23))

/*
 * 宏函数UCHAR_2_UINT(uchr8,uint32,i,notBigendian)
 * uchr8        -- unsigned char - 8bit
 * uint32       -- unsigned int  - 32bit
 * i            -- int
 * notBigendian -- int/bool
 * 将uchr8接收的字符数组,转换成大端表示的uint32（从底层看二进制按左高位右地位排列）
 * NOT_BIG_ENDIAN()检验环境，非大端时notBigendian为真，启用此宏函数
 */
#define UCHAR_2_UINT(uchr8,uint32,i,notBigendian)				\
{																\
	if(notBigendian){                                           \
		(uint32) = ((unsigned int) (uchr8)[(i)    ] << 24 )		\
				 | ((unsigned int) (uchr8)[(i) + 1] << 16 )		\
				 | ((unsigned int) (uchr8)[(i) + 2] << 8  )		\
				 | ((unsigned int) (uchr8)[(i) + 3]       );	\
	}															\
}

 /*
  * 宏函数UINT_2_UCHAR(uint32,uchr8,i,notBigendian)
  * uchr8        -- unsigned char - 8bit
  * uint32       -- unsigned int  - 32bit
  * i            -- int
  * notBigendian -- int/bool
  * 将大端表示的uint32,转换成uchr8的字符数组
  * NOT_BIG_ENDIAN()检验环境，非大端时notBigendian为真，启用此宏函数
  */
#define UINT_2_UCHAR(uint32,uchr8,i,notBigendian)				\
{																\
	if(notBigendian){                                           \
		(uchr8)[(i)    ] = (unsigned char)((uint32) >> 24);		\
		(uchr8)[(i) + 1] = (unsigned char)((uint32) >> 16);		\
		(uchr8)[(i) + 2] = (unsigned char)((uint32) >> 8 );		\
		(uchr8)[(i) + 3] = (unsigned char)((uint32)      );		\
	}															\
}

MsgInt MsgFill512(unsigned char* msg, int notBigendian);

ExtendMsgInt MsgExtend(unsigned int msgInt16[]);

void CF(unsigned int Vi[], unsigned int msgInt16[], unsigned int W[], unsigned int W1[]);

void SM3Hash(unsigned char* msgText, int notBigendian, unsigned char sm3HashChr32[]);

void SM3Interface();
