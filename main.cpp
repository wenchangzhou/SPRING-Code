
#include<math.h>
#include<time.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<math.h>
#include<iostream>   
#include<time.h>
#include<ctime>   
#include <memory.h>
using   namespace   std;
typedef unsigned int word32;
typedef unsigned char byte8;

void Make_Sbox_Table();
void S_Box_32bit(unsigned char NFSR[]);


int main() {
	uint8_t x[4], y[4], detax, temp[4];
	uint64_t i, j, k;
	
	uint8_t tempxor[4];
	uint64_t num = 0;
	uint64_t time = pow(2, 32);
	printf("%lld\n",time);
	clock_t start, finish, start1, finish1;
	float Total_time, Total_time1;
	Make_Sbox_Table();
	
	start = clock();

	for (i = 1; i < 256; i++) {
		detax = i;
		start1 = clock();
		for (j = 0; j < time; j++) {


			x[3] = j & 0x000000ff;
			x[2] = (j >> 8) & 0x000000ff;
			x[1] = (j >> 16) & 0x000000ff;
			x[0] = (j >> 24) & 0x000000ff;

			temp[0] = x[0] ^ detax;
			temp[1] = x[1];
			temp[2] = x[2];
			temp[3] = x[3];

			S_Box_32bit(x);
			S_Box_32bit(temp);
			tempxor[1] = x[1] ^ temp[1];
			tempxor[2] = x[2] ^ temp[2];
			tempxor[3] = x[3] ^ temp[3];

			if ((tempxor[1] == 0) && (tempxor[2] == 0) && (tempxor[3] == 0)) {


				num = num + 1;
			}

		}
		finish1 = clock();
		Total_time1 = (float)(finish1 - start1) / CLOCKS_PER_SEC / 3600; //单位换算成小时
		printf("%lld ROUND running time is %f hours\n", i, Total_time1);


	}


	printf("FIND!!!!!:   %lld\n", num);
	
	finish = clock();
	Total_time = (float)(finish - start) / CLOCKS_PER_SEC / 3600; //单位换算成小时
	printf("The total running time is %f hours\n", Total_time);

	return 0;
}