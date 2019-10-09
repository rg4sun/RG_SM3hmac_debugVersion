#include "SM3.h"

// 初始向量
const unsigned int IV[8] = {
	0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
	0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

//const unsigned int ipad[16] = {
//	0x36363636, 0x36363636, 0x36363636, 0x36363636,
//	0x36363636, 0x36363636, 0x36363636, 0x36363636,
//	0x36363636,	0x36363636, 0x36363636, 0x36363636,
//	0x36363636, 0x36363636, 0x36363636, 0x36363636
//};
//
//const unsigned int opad[16] = {
//	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
//	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
//	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
//	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c
//};

MsgInt MsgFill512(unsigned char* msg, int notBigendian)
{
	// int msgLength = sizeof(*msg) * 8; 指针数组长度不能用sizeof算
	//由于指针的特殊性，永远记录的首地址，而不记录所指向的数据的内存大小，因此指针数组无法求出长度
	//unsigned char msgArry[] = *msg; // 因此将值传入数组，数组可以计算长度...这样不合法
	//int msgLength = sizeof(msgArry) / sizeof(msgArry[0]) * 8; //。。。我好像忘了strlen了。，。
	MsgInt filledMsgInt;
	unsigned long long msgLength = strlen((char*)msg);// 这里必须有个强制转换，strlen不支持unsigned char*
	unsigned long long msgbitLength = msgLength * 8; // 求原始消息的比特长度
	int zeroFill = 448 - (msgbitLength + 8) % 512; // +8是补了0x80=0b1000_0000
	unsigned char* zeroChar = (unsigned char*)malloc(zeroFill / 8);

	memset(zeroChar, 0, zeroFill / 8);
	// 不能用strlen((char*)zeroChar),zeroChar全填0，而字符串结束标志就是0，所以strlen((char*)zeroChar)=0
	// 直接用memset从内存中拷贝值
	//zeroChar[zeroFill / 8] = '\0'; // 这个不需要加，直接从内存拷贝，不用确认是不是字符串，也无需加结束符
	// 实际上，zeroChar里面填充的全部0，在字符串识别来看都是结束符/0

	int totalChrLength = msgLength + 1 + zeroFill / 8 + 8;

	filledMsgInt.msgInt = (unsigned int*)malloc(totalChrLength / 4);
	filledMsgInt.intCount = totalChrLength / 4;//totalChrLength是字符个数8bit/个，msgInt为32bit/个

	unsigned char* msgFill = (unsigned char*)malloc(totalChrLength);// 1表示0x80的长度，一个字节
	memcpy(msgFill, msg, msgLength);
	unsigned char one = 0x80;
	memcpy(msgFill + msgLength, &one, 1);
	memcpy(msgFill + msgLength + 1, zeroChar, zeroFill / 8);
	//unsigned char* msgLenChr = (unsigned char*)msgLength;
	//memcpy(msgFill + msgLength + 1  + zeroFill / 8, msgLenChr, 8); // 这里填充有问题

	unsigned char msgLenChr[8];
	if (notBigendian) { // 小端系统，long long 都是在内存中颠倒存储的，所以需要转换
		for (int i = 0; i < 8; i++) {
			msgLenChr[i] = msgbitLength >> (56 - 8 * i);
		}
		memcpy(msgFill + msgLength + 1 + zeroFill / 8, msgLenChr, 8);
	}
	else { // 如果是大端系统，直接拷贝msgbitLength内存内容即可
		memcpy(msgFill + msgLength + 1 + zeroFill / 8, &msgbitLength, 8);
	}

	/*printf("%d\n", msgbitLength);
	printf("%d\n", zeroFill);
	printf("%d\n", zeroFill / 8);
	printf("%s\n", zeroChar);
	printf("%d\n", strlen(zeroChar));*/

	for (int i = 0; i < filledMsgInt.intCount; i++) {
		unsigned char msgSlice[4] = { *(msgFill + i * 4),*(msgFill + i * 4 + 1),*(msgFill + i * 4 + 2),*(msgFill + i * 4 + 3) };
		//unsigned int a = (unsigned int*)msgSlice;
		UCHAR_2_UINT(msgSlice, filledMsgInt.msgInt[i], 0, notBigendian);
	}

	return filledMsgInt;
}

ExtendMsgInt MsgExtend(unsigned int msgInt16[])
{
	ExtendMsgInt etdMsgInt;

	for (int i = 0; i < 16; i++) {
		etdMsgInt.W[i] = msgInt16[i];
	}
	for (int j = 16; j < 68; j++) {
		unsigned int tmp;
		tmp = etdMsgInt.W[j - 16] ^ etdMsgInt.W[j - 9] ^ ROTATE_LEFT(etdMsgInt.W[j - 3], 15);
		// 找到W数组会莫名被修改的原因了，是ROTATE_LEFT会改变传入的参数，现已修改了ROTATE_LEFT
		etdMsgInt.W[j] = P1(tmp) ^ ROTATE_LEFT(etdMsgInt.W[j - 13], 7) ^ etdMsgInt.W[j - 6];
	}
	for (int j = 0; j < 64; j++) {
		etdMsgInt.W1[j] = etdMsgInt.W[j] ^ etdMsgInt.W[j + 4];
	}
	return etdMsgInt;
}

void CF(unsigned int Vi[], unsigned int msgInt16[], unsigned int W[], unsigned int W1[])
{
	unsigned int regA2H[8]; // A~H 8个寄存器
	unsigned int SS1, SS2, TT1, TT2; // 中间变量

	for (int i = 0; i < 8; i++) {
		regA2H[i] = Vi[i];
	}
	for (int j = 0; j < 64; j++) {
		unsigned int T = 0x79cc4519; // 文档中的常量Tj，此处用T
		if (j >= 16) {
			T = 0x7a879d8a;
		}
		SS1 = ROTATE_LEFT(ROTATE_LEFT(regA2H[0], 12) + regA2H[4] + ROTATE_LEFT(T, j), 7);
		SS2 = SS1 ^ ROTATE_LEFT(regA2H[0], 12);
		if (j < 16) {
			TT1 = FF_LOW(regA2H[0], regA2H[1], regA2H[2]) + regA2H[3] + SS2 + W1[j];
			TT2 = GG_LOW(regA2H[4], regA2H[5], regA2H[6]) + regA2H[7] + SS1 + W[j];
		}
		else {
			TT1 = FF_HIGH(regA2H[0], regA2H[1], regA2H[2]) + regA2H[3] + SS2 + W1[j];
			TT2 = GG_HIGH(regA2H[4], regA2H[5], regA2H[6]) + regA2H[7] + SS1 + W[j];
		}
		regA2H[3] = regA2H[2];
		regA2H[2] = ROTATE_LEFT(regA2H[1], 9);
		regA2H[1] = regA2H[0];
		regA2H[0] = TT1;
		regA2H[7] = regA2H[6];
		regA2H[6] = ROTATE_LEFT(regA2H[5], 19);
		regA2H[5] = regA2H[4];
		regA2H[4] = P0(TT2);
	}
	for (int i = 0; i < 8; i++) { // 计算 ABCDEFH ^ Vi
		regA2H[i] ^= Vi[i];
		Vi[i] = regA2H[i];
	}
	//return regA2H;
}

void SM3Hash(unsigned char* msgText, int notBigendian, unsigned char sm3HashChr32[])
{
	MsgInt filledMsgInt = MsgFill512(msgText, notBigendian);
	// 对填充好的消息按512bit进行分组，即每16个int一组
	int groupAmount = filledMsgInt.intCount / 16;
	//unsigned int* V = IV;

	unsigned int V[8];
	for (int i = 0; i < 8; i++) {
		V[i] = IV[i];
	}
	for (int i = 0; i < groupAmount; i++) {
		unsigned int* bi = 16 * i + filledMsgInt.msgInt;
		ExtendMsgInt etdMsgInt = MsgExtend(bi);
		//unsigned int* temp = CF(V, bi, etdMsgInt.W, etdMsgInt.W1); // 每一轮压缩更新V
		//for (int i = 0; i < 8; i++) {
		//	V[i] = temp[i];
		//}
		CF(V, bi, etdMsgInt.W, etdMsgInt.W1); // 每一轮压缩更新V
	}
	// 直接输出int型的杂凑值测试
	/*for (int i = 0; i < 8; i++) {
		printf("%08x ", V[i]);
	}*/
	//return V;
	//unsigned char sm3HashValue[32];
	for (int i = 0; i < 8; i++) {
		UINT_2_UCHAR(V[i], sm3HashChr32, 4 * i, notBigendian);
	}
}

void SM3hmac(unsigned char msgText[], unsigned int keyInt16[], int notBigendian, unsigned char sm3hmacChr32[])
{
	// 因为默认使用自己随机出来的key，随机的时候规定生成的key就是64Byte，就不需要填充key至64Byte
	unsigned int tempInt16[32]; // ipad opad一起算了，tempInt前16个元素存储和ipad异或结果，后16个元素存储opad异或结果
	for (int i = 0; i < 16; i++) {
		tempInt16[i] = keyInt16[i] ^ 0x36363636;//ipad[i];
		tempInt16[i + 16] = keyInt16[i] ^ 0x5c5c5c5c;// opad[i];
	}
	unsigned char keyChr64[128]; // 前64存储ipad异或结果(int)转成char，后64存储opad
	for (int i = 0; i < 16; i++) {
		UINT_2_UCHAR(tempInt16[i], keyChr64, 4 * i, notBigendian);
		UINT_2_UCHAR(tempInt16[i + 16], keyChr64, 4 * (i + 16), notBigendian);
		// 不是很懂为啥这里 第二个参数不用 keyChr64 + 64，照理来说，应该要是 &keyChr64[64] 不就是 keyChr64 + 64么
	}
	unsigned char* jointChr = (unsigned char*)malloc((strlen(msgText) + 64) * sizeof(unsigned char));// 第一次hash前的拼接长度
	memcpy(jointChr, keyChr64, 64);
	memcpy(jointChr + 64, msgText, strlen(msgText));
	//memcpy(jointChr + strlen(msgText), 0, 1); 这个不能放常量0，要放指针进去
	memset(jointChr + 64 + strlen(msgText), 0, 1);
	// 一定要在末尾添上\0标志字符串结尾，否则后续调用msgFill512时候读取msgLength会有错误，
	// 这让我想到另一个问题，如果key里面有全零字符就会出现问题，比如key有一段为 0x61 62 00 63
	// 他算长度只算到62这个字符结束，后续实际在key里面的字符，会因为00的出现而被阻断
	//unsigned char sm3HashChr32[32];
	SM3Hash(jointChr, notBigendian, sm3hmacChr32);
	//free(jointChr);// 释放内存
	jointChr = (unsigned char*)malloc((64 + 32) * sizeof(unsigned char)); // 第二次hash前的拼接长度
	memcpy(jointChr, keyChr64 + 64, 64);
	memcpy(jointChr + 64, sm3hmacChr32, 32);
	memset(jointChr + 64 + 32, 0, 1);
	SM3Hash(jointChr, notBigendian, sm3hmacChr32);

}

void SM3Interface()
{

}

