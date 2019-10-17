#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include"SM3.h"

#include<Windows.h> // Linux下注释掉此行

#pragma warning(disable : 4996)// 用于微软VS标准 // Linux下注释掉此行

// SM3所有操作已完成，以下为测试函数了
// 填充和扩展的输出测试
void Fill_N_extend_test(unsigned char chr[])
{
	int bigendFlag = NOT_BIG_ENDIAN();

	//unsigned char* chr = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

	MsgInt filledMsgInt = MsgFill512(chr, bigendFlag);
	//unsigned char ch[] = *chr; 
	int groupAmount = filledMsgInt.intCount / 16;

	//消息填充输出测试
	puts("------- 消息填充输出测试 -------\n");
	for (int i = 0; i < filledMsgInt.intCount; i++) {
		printf("%08x ", filledMsgInt.msgInt[i]);
	}

	//消息扩展输出测试
	for (int i = 0; i < groupAmount; i++) {
		unsigned int* bi = 16 * i + filledMsgInt.msgInt;
		ExtendMsgInt etdMsgInt = MsgExtend(bi);
		printf("\n\n------- 消息扩展输出测试 第%d组-------\n", i + 1);
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

// 文档示例一
void Eg1_test() {
	int bigendFlag = NOT_BIG_ENDIAN();

	unsigned char* chr = "abc";
	//unsigned char* hashChr = SM3Hash_Old(chr, bigendFlag);
	unsigned char hashChr[32];

	SM3Hash(chr, bigendFlag, hashChr);

	puts("-------------------- 文档示例1 --------------------\n\n");
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

// 文档示例二
void Eg2_test() {
	int bigendFlag = NOT_BIG_ENDIAN();
	unsigned char* chr = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

	//unsigned char* hashChr = SM3Hash_Old(chr, bigendFlag);
	// 运算没问题，但是返回给指针之后到下面的puts调用时，会破坏hashChr指向的内存内容
	unsigned char hashChr[32];

	SM3Hash(chr, bigendFlag, hashChr);

	puts("-------------------- 文档示例2 --------------------\n\n");
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
	puts("密钥：");
	for (int i = 0; i < 16; i++) {
		printf("%08x ", keyInt16[i]);
	}
	printf("\n-------------------------------------------------\n");
	unsigned char sm3hmacValue[32];
	unsigned char* msg = "abcd";
	clock_t start, end;
	double excuteTime;
	start = clock();
	SM3hmac(msg, keyInt16, bigendFlag, sm3hmacValue);
	end = clock();

	excuteTime = ((double)end - (double)start) / CLOCKS_PER_SEC;
	puts("hmac:");
	HmacPrint(sm3hmacValue);
	printf("完成SM3hmac所用时间: %f seconds.\n", excuteTime);
}

void fileReadTest()
{
	FILE* fp;
	char* filename = "msg.txt";//"rawKeyFile.txt"; // /t 会被识别为转义字符
	int fileChrAmount = 3072;
	unsigned char* msg = (unsigned char*)malloc(fileChrAmount * sizeof(unsigned char));
	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("Cannot open  %s\n", filename);
		exit(0);
	}
	fgets(msg, fileChrAmount + 1, fp); // +1原因如下
	//char *fgets(char *str,int n,FILE *fp)
	//从由fp指出的文件中读取n-1个字符，并把它们存放到由str指出的字符数组中去，最后加上一个字符串结束符'\0'
	printf("Your msg show as below:\n%s\n", msg);
	printf("\n------------------------------------\nCharacter Amount: %d\n", strlen(msg));
	fclose(fp);
}

int main()
{
	
	char* filename = "msg.txt";
	int fileChrAmount = 3145728;

	SM3hmacWithFile(filename, fileChrAmount);

	//system("pause"); // Linux下注释掉此行

	return 0;
}