#include "SM3.h"

// ��ʼ����
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
	// int msgLength = sizeof(*msg) * 8; ָ�����鳤�Ȳ�����sizeof��
	//����ָ��������ԣ���Զ��¼���׵�ַ��������¼��ָ������ݵ��ڴ��С�����ָ�������޷��������
	//unsigned char msgArry[] = *msg; // ��˽�ֵ�������飬������Լ��㳤��...�������Ϸ�
	//int msgLength = sizeof(msgArry) / sizeof(msgArry[0]) * 8; //�������Һ�������strlen�ˡ�����
	MsgInt filledMsgInt;
	unsigned long long msgLength = strlen((char*)msg);// ��������и�ǿ��ת����strlen��֧��unsigned char*
	unsigned long long msgbitLength = msgLength * 8; // ��ԭʼ��Ϣ�ı��س���
	int zeroFill = 448 - (msgbitLength + 8) % 512; // +8�ǲ���0x80=0b1000_0000
	unsigned char* zeroChar = (unsigned char*)malloc(zeroFill / 8);

	memset(zeroChar, 0, zeroFill / 8);
	// ������strlen((char*)zeroChar),zeroCharȫ��0�����ַ���������־����0������strlen((char*)zeroChar)=0
	// ֱ����memset���ڴ��п���ֵ
	//zeroChar[zeroFill / 8] = '\0'; // �������Ҫ�ӣ�ֱ�Ӵ��ڴ濽��������ȷ���ǲ����ַ�����Ҳ����ӽ�����
	// ʵ���ϣ�zeroChar��������ȫ��0�����ַ���ʶ���������ǽ�����/0

	int totalChrLength = msgLength + 1 + zeroFill / 8 + 8;

	filledMsgInt.msgInt = (unsigned int*)malloc(totalChrLength / 4);
	filledMsgInt.intCount = totalChrLength / 4;//totalChrLength���ַ�����8bit/����msgIntΪ32bit/��

	unsigned char* msgFill = (unsigned char*)malloc(totalChrLength);// 1��ʾ0x80�ĳ��ȣ�һ���ֽ�
	memcpy(msgFill, msg, msgLength);
	unsigned char one = 0x80;
	memcpy(msgFill + msgLength, &one, 1);
	memcpy(msgFill + msgLength + 1, zeroChar, zeroFill / 8);
	//unsigned char* msgLenChr = (unsigned char*)msgLength;
	//memcpy(msgFill + msgLength + 1  + zeroFill / 8, msgLenChr, 8); // �������������

	unsigned char msgLenChr[8];
	if (notBigendian) { // С��ϵͳ��long long �������ڴ��еߵ��洢�ģ�������Ҫת��
		for (int i = 0; i < 8; i++) {
			msgLenChr[i] = msgbitLength >> (56 - 8 * i);
		}
		memcpy(msgFill + msgLength + 1 + zeroFill / 8, msgLenChr, 8);
	}
	else { // ����Ǵ��ϵͳ��ֱ�ӿ���msgbitLength�ڴ����ݼ���
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
		// �ҵ�W�����Ī�����޸ĵ�ԭ���ˣ���ROTATE_LEFT��ı䴫��Ĳ����������޸���ROTATE_LEFT
		etdMsgInt.W[j] = P1(tmp) ^ ROTATE_LEFT(etdMsgInt.W[j - 13], 7) ^ etdMsgInt.W[j - 6];
	}
	for (int j = 0; j < 64; j++) {
		etdMsgInt.W1[j] = etdMsgInt.W[j] ^ etdMsgInt.W[j + 4];
	}
	return etdMsgInt;
}

void CF(unsigned int Vi[], unsigned int msgInt16[], unsigned int W[], unsigned int W1[])
{
	unsigned int regA2H[8]; // A~H 8���Ĵ���
	unsigned int SS1, SS2, TT1, TT2; // �м����

	for (int i = 0; i < 8; i++) {
		regA2H[i] = Vi[i];
	}
	for (int j = 0; j < 64; j++) {
		unsigned int T = 0x79cc4519; // �ĵ��еĳ���Tj���˴���T
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
	for (int i = 0; i < 8; i++) { // ���� ABCDEFH ^ Vi
		regA2H[i] ^= Vi[i];
		Vi[i] = regA2H[i];
	}
	//return regA2H;
}

void SM3Hash(unsigned char* msgText, int notBigendian, unsigned char sm3HashChr32[])
{
	MsgInt filledMsgInt = MsgFill512(msgText, notBigendian);
	// �����õ���Ϣ��512bit���з��飬��ÿ16��intһ��
	int groupAmount = filledMsgInt.intCount / 16;
	//unsigned int* V = IV;

	unsigned int V[8];
	for (int i = 0; i < 8; i++) {
		V[i] = IV[i];
	}
	for (int i = 0; i < groupAmount; i++) {
		unsigned int* bi = 16 * i + filledMsgInt.msgInt;
		ExtendMsgInt etdMsgInt = MsgExtend(bi);
		//unsigned int* temp = CF(V, bi, etdMsgInt.W, etdMsgInt.W1); // ÿһ��ѹ������V
		//for (int i = 0; i < 8; i++) {
		//	V[i] = temp[i];
		//}
		CF(V, bi, etdMsgInt.W, etdMsgInt.W1); // ÿһ��ѹ������V
	}
	// ֱ�����int�͵��Ӵ�ֵ����
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
	// ��ΪĬ��ʹ���Լ����������key�������ʱ��涨���ɵ�key����64Byte���Ͳ���Ҫ���key��64Byte
	unsigned int tempInt16[32]; // ipad opadһ�����ˣ�tempIntǰ16��Ԫ�ش洢��ipad���������16��Ԫ�ش洢opad�����
	for (int i = 0; i < 16; i++) {
		tempInt16[i] = keyInt16[i] ^ 0x36363636;//ipad[i];
		tempInt16[i + 16] = keyInt16[i] ^ 0x5c5c5c5c;// opad[i];
	}
	unsigned char keyChr64[128]; // ǰ64�洢ipad�����(int)ת��char����64�洢opad
	for (int i = 0; i < 16; i++) {
		UINT_2_UCHAR(tempInt16[i], keyChr64, 4 * i, notBigendian);
		UINT_2_UCHAR(tempInt16[i + 16], keyChr64, 4 * (i + 16), notBigendian);
		// ���Ǻܶ�Ϊɶ���� �ڶ����������� keyChr64 + 64��������˵��Ӧ��Ҫ�� &keyChr64[64] ������ keyChr64 + 64ô
	}
	unsigned char* jointChr = (unsigned char*)malloc((strlen(msgText) + 64) * sizeof(unsigned char));// ��һ��hashǰ��ƴ�ӳ���
	memcpy(jointChr, keyChr64, 64);
	memcpy(jointChr + 64, msgText, strlen(msgText));
	//memcpy(jointChr + strlen(msgText), 0, 1); ������ܷų���0��Ҫ��ָ���ȥ
	memset(jointChr + 64 + strlen(msgText), 0, 1);
	// һ��Ҫ��ĩβ����\0��־�ַ�����β�������������msgFill512ʱ���ȡmsgLength���д���
	// �������뵽��һ�����⣬���key������ȫ���ַ��ͻ�������⣬����key��һ��Ϊ 0x61 62 00 63
	// ���㳤��ֻ�㵽62����ַ�����������ʵ����key������ַ�������Ϊ00�ĳ��ֶ������
	//unsigned char sm3HashChr32[32];
	SM3Hash(jointChr, notBigendian, sm3hmacChr32);
	//free(jointChr);// �ͷ��ڴ�
	jointChr = (unsigned char*)malloc((64 + 32) * sizeof(unsigned char)); // �ڶ���hashǰ��ƴ�ӳ���
	memcpy(jointChr, keyChr64 + 64, 64);
	memcpy(jointChr + 64, sm3hmacChr32, 32);
	memset(jointChr + 64 + 32, 0, 1);
	SM3Hash(jointChr, notBigendian, sm3hmacChr32);

}

void SM3Interface()
{

}

