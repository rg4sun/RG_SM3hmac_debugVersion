#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include"SM3.h"

#include<Windows.h> // Linux��ע�͵�����

#pragma warning(disable : 4996)// ����΢��VS��׼ // Linux��ע�͵�����

// SM3���в�������ɣ�����Ϊ���Ժ�����
// ������չ���������
void Fill_N_extend_test(unsigned char chr[])
{
	int bigendFlag = NOT_BIG_ENDIAN();

	//unsigned char* chr = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

	MsgInt filledMsgInt = MsgFill512(chr, bigendFlag);
	//unsigned char ch[] = *chr; 
	int groupAmount = filledMsgInt.intCount / 16;

	//��Ϣ����������
	puts("------- ��Ϣ���������� -------\n");
	for (int i = 0; i < filledMsgInt.intCount; i++) {
		printf("%08x ", filledMsgInt.msgInt[i]);
	}

	//��Ϣ��չ�������
	for (int i = 0; i < groupAmount; i++) {
		unsigned int* bi = 16 * i + filledMsgInt.msgInt;
		ExtendMsgInt etdMsgInt = MsgExtend(bi);
		printf("\n\n------- ��Ϣ��չ������� ��%d��-------\n", i + 1);
		printf("\nW0---W67:\n");
		for (int i = 0; i < 68; i++) {
			printf("%08x ", etdMsgInt.W[i]);
		}
		printf("\n\nW1_0----W1_63:\n");
		for (int i = 0; i < 64; i++) {
			printf("%08x ", etdMsgInt.W1[i]);
		}
		printf("\n");
	}

}

// �ĵ�ʾ��һ
void Eg1_test() {
	int bigendFlag = NOT_BIG_ENDIAN();

	unsigned char* chr = "abc";
	//unsigned char* hashChr = SM3Hash_Old(chr, bigendFlag);
	unsigned char hashChr[32];

	SM3Hash(chr, bigendFlag, hashChr);

	puts("-------------------- �ĵ�ʾ��1 --------------------\n\n");
	//Fill_N_extend_test(chr);
	puts("\n Eg1 hash value: ");
	for (int i = 0; i < 32; i++) {
		printf("%02x", hashChr[i]);
		if (i != 0 && i % 4 == 0) {
			printf(" ");
		}
	}
	printf("\n");
}

// �ĵ�ʾ����
void Eg2_test() {
	int bigendFlag = NOT_BIG_ENDIAN();
	unsigned char* chr = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

	//unsigned char* hashChr = SM3Hash_Old(chr, bigendFlag);
	// ����û���⣬���Ƿ��ظ�ָ��֮�������puts����ʱ�����ƻ�hashChrָ����ڴ�����
	unsigned char hashChr[32];

	SM3Hash(chr, bigendFlag, hashChr);

	puts("-------------------- �ĵ�ʾ��2 --------------------\n\n");
	//Fill_N_extend_test(chr);
	puts("\n Eg2 hash value: ");
	for (int i = 0; i < 32; i++) {
		printf("%02x", hashChr[i]);
		if (i != 0 && i % 4 == 0) {
			printf(" ");
		}
	}
	printf("\n");
}

void otherTest()
{
	char s[20] = { 0x61,0x62,0x63,0x00,0x00,'s','e' };

	printf("%d\n", strlen(s));
	printf("%s\n", s);
}

void HmacPrint(unsigned char hmac32[])
{
	for (int i = 0; i < 32; i++) {
		printf("%02x", hmac32[i]);
		if (i != 0 && i % 4 == 0) {
			printf(" ");
		}
	}
	printf("\n");
}

void hmacTest()
{
	int bigendFlag = NOT_BIG_ENDIAN();
	unsigned char sm3hmacValue[32];

	char* str = "abcd";
	/*unsigned int key[16] = {
		0x61626364, 0x61626364, 0x61626364, 0x61626364,
		0x61626364, 0x61626364, 0x61626364, 0x61626364,
		0x61626364, 0x61626364, 0x61626364, 0x61626364,
		0x61626364, 0x61626364, 0x61626364, 0x61626364
	};*/

	unsigned int key[16] = {
		0x23242526, 0x61626364, 0x12131415, 0x41424364,
		0x23242526, 0x61626364, 0x12131415, 0x41424364,
		0x23242526, 0x61626364, 0x12131415, 0x41424364,
		0x23242526, 0x61626364, 0x12131415, 0x41424364
	};
	SM3hmac(str, key, bigendFlag, sm3hmacValue);

	HmacPrint(sm3hmacValue);
	
}

void keyNhamcTest()
{
	//Eg1_test();
	int bigendFlag = NOT_BIG_ENDIAN();
	unsigned int keyInt16[16];
	Key16Generate(keyInt16, bigendFlag);
	unsigned char sm3hmacValue[32];
	unsigned char* msg = "abcd";

	SM3hmac(msg, keyInt16, bigendFlag, sm3hmacValue);

	HmacPrint(sm3hmacValue);
}

int main()
{
	

	//system("pause"); // Linux��ע�͵�����

	return 0;
}