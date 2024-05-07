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
int key_round_num=0;
unsigned char Sbox0[256][256];
unsigned char Sbox1[256][256];
unsigned char Sbox2[256][256];
unsigned char Sbox3[256][256];
int flag0=1;

void Count_Sbox(unsigned char NFSR[])
{
	int i,j,k,step;
	unsigned char f[4];
	for(step=0;step<4;step++)
	{
		f[0]=NFSR[0]^((NFSR[0]>>3)&(NFSR[0]>>4))^(NFSR[0]>>6)^NFSR[3]^NFSR[2];
		f[1]=NFSR[1]^((NFSR[1]>>3)&(NFSR[1]>>4))^(NFSR[1]>>5)^NFSR[0]^NFSR[3];
		f[2]=NFSR[2]^((NFSR[2]>>4)&(NFSR[2]>>5))^(NFSR[2]>>3)^NFSR[1]^NFSR[0];
		f[3]=NFSR[3]^((NFSR[3]>>4)&(NFSR[3]>>5))^(NFSR[3]>>2)^NFSR[2]^NFSR[1];
		for(i=0;i<4;i++)
			NFSR[i]=(NFSR[i]>>2)^((f[i]&0x03)<<6);
	}
}

void Make_Sbox_Table()
{
	unsigned char N[4];
	unsigned int St,St2;
	for(St2=0;St2<256;St2++)
	{
		for(St=0;St<256;St++)
		{
			N[3]=St2;
			N[2]=0;
			N[0]=St;
			Count_Sbox(N);
			Sbox0[St2][St]=N[0];
			N[3]=St2;
			N[0]=0;
			N[1]=St;
			Count_Sbox(N);
			Sbox1[St2][St]=N[1];
			N[0]=St2;
			N[1]=0;
			N[2]=St;
			Count_Sbox(N);
			Sbox2[St2][St]=N[2];
			N[1]=St2;
			N[2]=0;
			N[3]=St;
			Count_Sbox(N);
			Sbox3[St2][St]=N[3];
		}
	}
}

void up_side_down_NFSRs(unsigned int *valu,int length,int number)//将寄存器状态倒置
{
	int i,j,k,l;
	unsigned int temp;
	for(i=0;i<number;i++)
	{
		temp=*(valu+i);
		*(valu+i)=0;
		for(j=0;j<length/2;j++)
			*(valu+i)=*(valu+i)^((temp&(0x01<<j))<<(length-1-2*j))^((temp&(0x01<<(length-j-1)))>>(length-1-2*j));
	}
	for(i=0;i<number/2;i++)
	{
		temp=*(valu+i);
		*(valu+i)=*(valu+number-1-i);
		*(valu+number-1-i)=temp;
	}
}

void Key_NFSR_update(unsigned int CS,unsigned int KS[]) 
	//加密密钥寄存器更新函数（每次调用更新Key_lfsr_step拍，Key_lfsr_step与寄存器长度相等）
{
	int i,j,k,l,n=0;
	unsigned int f[8],fc,flag=0xffff;
	int num1,num2,num3,num4;
	{	num1=3;num2=8;num3=7;num4=10;}										//keylen=128对应抽头位置
	KS[0]=KS[0]^(CS<<(8));										//加常值
	for(k=0;k<16;k++)
	{
		for(j=0;j<4;j++)
		{
			f[j]=( (KS[j]>>1)^(KS[j]>>(num1+j))^( (KS[j]>>(num2+1))&(KS[j]>>num2) )^( KS[(j+7)&0x7] ) )&0x01;												//前4个寄存器更新函数
			f[j+4]=( (KS[j+4]>>(15))^(KS[j+4]>>(num4+j))^( (KS[j+4]>>num3)&(KS[j+4]>>(num3+1)))^( KS[(j+3)] ) )&0x01 ;		//后4个寄存器更新函数
		}
		for(j=0;j<8;j++)
			KS[j]=(((KS[j]&flag)>>1)^((f[j]&0x01)<<(15)));			//寄存器移位
	}
}

void  inv_Key_NFSR_update(unsigned char CS,unsigned int KS[]) 
	//解密密钥寄存器更新函数（每次调用更新Key_lfsr_step拍，Key_lfsr_step与寄存器长度相等）
{
	int i,j,k,l,n=0;
	unsigned int f[8],fc,flag=0xffff;
	int num1,num2,num3,num4;
		{	num1=3;num2=8;num3=7;num4=10;}											//keylen=128对应抽头位置
		for(k=0;k<16;k++)
		{
			for(j=0;j<4;j++)
			{
				f[j]=( (KS[j]>>1)^(KS[j]>>(num1+j))^( (KS[j]>>(num2+1))&(KS[j]>>num2) ) ^KS[j])&0x01;														//前4个寄存器更新函数
				f[j+4]=( (KS[j+4]>>(15))^(KS[j+4]>>(num4+j))^( (KS[j+4]>>num3)&(KS[j+4]>>(num3+1)))^KS[j+4])&0x01 ;	//后4个寄存器更新函数
			}
			for(j=0;j<8;j++)
				KS[j]=((KS[j]>>1)^((f[(j+7)&0x07])<<(15)))&flag;				//寄存器移位
		}
		KS[7]=KS[7]^(CS);
}

int Key_Schedule(unsigned char *Seedkey, int KeyLen, unsigned   //密钥扩展算法   
char Direction, unsigned char *Subkey)		//此处相较《要求》多了分组长度（in_len）这一参数//0 加密，1 解密
{
	if((KeyLen!=16)||(Direction!=0&&Direction!=1)) return -1;
	unsigned int CS1[18]={0xc0,0x24,0x3b,0x41,0x6d,0x4d,0xc3,0xb7,0xd7,0x45,0xd8,0x78,0xce,0x68,0x89,0x52,0xb9,0x9b};//加密轮常值
	unsigned int CS2[18]={0x3,0x24,0xdc,0x82,0xb6,0xb2,0xc3,0xed,0xeb,0xa2,0x1b,0x1e,0x73,0x16,0x91,0x4a,0x9d,0xd9};	//解密轮常值
	int i,j,k,l,count,n=0,
	roundnum=10,
		Key_lfsr_step=16;		//密钥寄存器拍数
	if(key_round_num!=0) roundnum=key_round_num;
	unsigned int KS[8],f[8],fc;
	int bunch_num_in_NFSR=2;		//每个密钥寄存器中包含多少个8bit块=KeyLen(8块*8bit)    2/4
	int Bit_num_one_bunch=16;		//每个密钥寄存器长度															  16/32
	int step=1;								//跳几个寄存器取一次密钥值													1/2/1
	for(i=0;i<8;i++)
		for(j=0;j<bunch_num_in_NFSR;j++)
			KS[i]=*(Seedkey+bunch_num_in_NFSR*i+j)+(KS[i]<<8);		//装载寄存器状态
	if(!Direction)
	{
		count=0;
		while(count<8)
		{
			for(k=0;k<bunch_num_in_NFSR;k++)
				*(Subkey+n++)=(KS[count]>>8*(bunch_num_in_NFSR-1-k));	//取寄存器状态作子密钥
			count=count+step;
		}
		for(i=0;i<roundnum;i++)
		{
			 Key_NFSR_update(CS1[i],KS);
			count=0;
			while(count<8)
			{
				for(k=0;k<bunch_num_in_NFSR;k++)
					*(Subkey+n++)=(KS[count]>>8*(bunch_num_in_NFSR-1-k));	//取寄存器状态作子密钥
				count=count+step;
			}
		}
	}
	else
	{
		int startpoint=0;
		for(i=0;i<roundnum;i++)
			 Key_NFSR_update(CS1[i],KS);		//接下来把KS倒装，进行逆更新，存到Subkey中。
		up_side_down_NFSRs(KS,Bit_num_one_bunch,8);				//将寄存器状态倒置
		count=startpoint;
		while(count<8)
		{
			for(k=0;k<bunch_num_in_NFSR;k++)
				*(Subkey+n++)=(KS[count]>>8*(bunch_num_in_NFSR-1-k))&0xff;	
			count=count+step;
		}
		for(i=roundnum-1;i>=0;i--)
		{
			inv_Key_NFSR_update(CS2[i],KS);
			count=startpoint;
			while(count<8)
			{
				for(k=0;k<bunch_num_in_NFSR;k++)
					*(Subkey+n++)=(KS[count]>>8*(bunch_num_in_NFSR-1-k))&0xff;	
				count=count+step;
			}
		}
	}
	return 0;
}

void Addroundkey(unsigned char S[][4],int round,unsigned char *Subkey,int in_len)
{
	int i,j,k,l;
	for(i=0;i<4;i++)	
		for(j=0;j<4;j++)
			S[i][j]=S[i][j]^*(Subkey+(i<<2)+j+round*16);
}

void S_Box_32bit(unsigned char NFSR[])
{
	int i,j,k,step;
	unsigned char f[4];
	for(step=0;step<4;step++)
	{
		f[0]=NFSR[0];f[1]=NFSR[1];f[2]=NFSR[2];
		NFSR[0]=Sbox0[(NFSR[2]^NFSR[3])][NFSR[0]];
		NFSR[1]=Sbox1[(f[0]^NFSR[3])][NFSR[1]];
		NFSR[2]=Sbox2[(f[0]^f[1])][NFSR[2]];
		NFSR[3]=Sbox3[(f[2]^f[1])][NFSR[3]];
	}
}

void inv_S_Box_32bit(unsigned char NFSR[])
{
	int i,j,k,step;
	unsigned char f[4],sum=0;
	for(step=0;step<32;step++)
	{
		f[0]=NFSR[0]^((NFSR[0]>>3)&(NFSR[0]>>4))^(NFSR[0]>>6);
		f[1]=NFSR[1]^((NFSR[1]>>3)&(NFSR[1]>>4))^(NFSR[1]>>5);
		f[2]=NFSR[2]^((NFSR[2]>>4)&(NFSR[2]>>5))^(NFSR[2]>>3);
		f[3]=NFSR[3]^((NFSR[3]>>4)&(NFSR[3]>>5))^(NFSR[3]>>2);
		sum=f[0]^f[1]^f[2]^f[3];
		for(i=0;i<4;i++)
			NFSR[i]=(NFSR[i]>>1)^(((sum^f[(i+1)&0x03])&0x01)<<7);
	}
}

void L_layer(unsigned char S[][4],int in_len)
{
	int Sbox_num=3;
	unsigned char SL[4][4];
	int i,j,k,l;
	for(i=0;i<=Sbox_num;i++)
		for(j=0;j<4;j++)
			SL[i][j]=S[i][j];
	for(i=0;i<=Sbox_num;i++)
		for(j=0;j<4;j++)
			S[i][j]=((SL[Sbox_num-i][3-j]&(0x01))<<7)^
						((SL[Sbox_num-i][3-j]&(0x02))<<5)^
						((SL[Sbox_num-i][3-j]&(0x04))<<3)^
						((SL[Sbox_num-i][3-j]&(0x08))<<1)^
						((SL[Sbox_num-i][3-j]&(0x10))>>1)^
						((SL[Sbox_num-i][3-j]&(0x20))>>3)^
						((SL[Sbox_num-i][3-j]&(0x40))>>5)^
						((SL[Sbox_num-i][3-j]&(0x80))>>7);
}

void P_Layer(unsigned char S[][4],int in_len)
{
	int i,j,k,l;
	unsigned char SP[4][4];
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			SP[i][j]=S[i][j];
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			S[i][j]=SP[j][i];
}

int Crypt_Enc_Block_Round(unsigned char *input,int in_len,  unsigned 
char *output, int *out_len, unsigned char *key, int keylen, int CryptRound)
{
	if(flag0) {Make_Sbox_Table();flag0=0;}
	if((in_len&0xf)||(keylen!=16)) 
		return -1;
	int round=0,flag=0;
	unsigned char Direction=0;
	unsigned char Subkey[800];
	int roundnum=10;
	key_round_num=CryptRound;
	if(CryptRound>=roundnum) {flag=1;}
	Key_Schedule(key, keylen, Direction, Subkey);
	unsigned char S[4][4];
	int i,j,k=0,l,f[3],step,n;
	for(n=0;n<(in_len>>4);n++)
	{
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			S[i][j]=*(input+4*i+j+16*n);
	Addroundkey(S,0,Subkey,in_len);
	for(round=0;round<CryptRound;round++)
	{
		for(i=0;i<4;i++)
			for(step=0;step<4;step++)
			{
				f[0]=S[i][0];f[1]=S[i][1];f[2]=S[i][2];
				S[i][0]=Sbox0[(S[i][2]^S[i][3])][S[i][0]];
				S[i][1]=Sbox1[(f[0]^S[i][3])][S[i][1]];
				S[i][2]=Sbox2[(f[0]^f[1])][S[i][2]];
				S[i][3]=Sbox3[(f[2]^f[1])][S[i][3]];
			}	
			if((round+1)==CryptRound) {P_Layer(S,in_len);break;}
		for(i=0;i<4;i++)	
			for(j=0;j<4;j++)
				S[i][j]=S[i][j]^*(Subkey+(j<<2)+i+(round+1)*16);
		round++;
		for(i=0;i<4;i++)
			for(step=0;step<4;step++)
			{
				f[0]=S[0][i];f[1]=S[1][i];f[2]=S[2][i];
				S[0][i]=Sbox0[(S[2][i]^S[3][i])][S[0][i]];
				S[1][i]=Sbox1[(f[0]^S[3][i])][S[1][i]];
				S[2][i]=Sbox2[(f[0]^f[1])][S[2][i]];
				S[3][i]=Sbox3[(f[2]^f[1])][S[3][i]];
			}
		if(round==(CryptRound-1))
		{	
			if(!flag) break;
			P_Layer(S,in_len);
		}
		for(i=0;i<4;i++)	
				for(j=0;j<4;j++)
					S[i][j]=S[i][j]^*(Subkey+(i<<2)+j+(round+1)*16);
	}
	if(flag)
		L_layer(S,in_len);
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			*(output+k++)=S[i][j];
	}
	*(out_len)=k;
	key_round_num=0;
	return 0;
}

int Crypt_Dec_Block(unsigned char *input,int in_len, unsigned char 
*output,int *out_len, unsigned char *key, int keylen)
{
	if((in_len&0xf)||(keylen!=16)) return -1;
	int round=0;
	unsigned char Direction=1;
	unsigned char Subkey[800];
	int CryptRound=10;
	Key_Schedule(key, keylen, Direction, Subkey);
	unsigned char S[4][4];
	int i,j,k=0,l,n;
	for(n=0;n<(in_len>>4);n++)
	{
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			S[i][j]=*(input+4*i+j+16*n);
	round=0;
	Addroundkey(S,round++,Subkey,in_len);
	for(round;round<CryptRound;round++)
	{
		for(i=0;i<4;i++)
			inv_S_Box_32bit(S[i]);
		Addroundkey(S,round,Subkey,in_len);
		P_Layer(S,in_len);
	}
	for(i=0;i<4;i++)
		inv_S_Box_32bit(S[i]);
	Addroundkey(S,round,Subkey,in_len);
	L_layer(S,in_len);
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			*(output+k++)=S[i][j];
	}
	*(out_len)=k;
	return 0;
}

int Crypt_Enc_Block(unsigned char *input,int in_len, unsigned char  
*output, int *out_len, unsigned char *key , int keylen)
{
	if(flag0) {Make_Sbox_Table();flag0=0;}
		if((in_len&0xf)||(keylen!=16)) return -1;
	int round=0;
	unsigned char Direction=0;
	unsigned char Subkey[800];
	Key_Schedule(key, keylen, Direction, Subkey);
	unsigned char S[4][4];
	int i,j,k=0,l,f[3],step,n;
	int CryptRound=10;//按照输入和密钥长度确定轮数

	for(n=0;n<(in_len>>4);n++)
	{
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			S[i][j]=*(input+4*i+j+16*n);
	Addroundkey(S,0,Subkey,in_len);
	for(round=0;round<CryptRound/2;round++)
	{
		for(i=0;i<4;i++)
			for(step=0;step<4;step++)
			{
				f[0]=S[i][0];f[1]=S[i][1];f[2]=S[i][2];
				S[i][0]=Sbox0[(S[i][2]^S[i][3])][S[i][0]];
				S[i][1]=Sbox1[(f[0]^S[i][3])][S[i][1]];
				S[i][2]=Sbox2[(f[0]^f[1])][S[i][2]];
				S[i][3]=Sbox3[(f[2]^f[1])][S[i][3]];
			}
		for(i=0;i<4;i++)	
			for(j=0;j<4;j++)
				S[i][j]=S[i][j]^*(Subkey+(j<<2)+i+(2*round+1)*16);
		for(i=0;i<4;i++)
			for(step=0;step<4;step++)
			{
				f[0]=S[0][i];f[1]=S[1][i];f[2]=S[2][i];
				S[0][i]=Sbox0[(S[2][i]^S[3][i])][S[0][i]];
				S[1][i]=Sbox1[(f[0]^S[3][i])][S[1][i]];
				S[2][i]=Sbox2[(f[0]^f[1])][S[2][i]];
				S[3][i]=Sbox3[(f[2]^f[1])][S[3][i]];
			}
		if(round==CryptRound/2-1)
			P_Layer(S,in_len);
		for(i=0;i<4;i++)	
			for(j=0;j<4;j++)
				S[i][j]=S[i][j]^*(Subkey+(i<<2)+j+2*(round+1)*16);
	}
	L_layer(S,in_len);
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			*(output+k++)=S[i][j];
	}
	*(out_len)=k;
	return 0;
}

int Crypt_Enc_Block_CBC( unsigned char * input, int in_len, unsigned char * output, int * out_len, unsigned char * key, int keylen )
{
	int s1=0,s2=0;
	unsigned char c[16]={0},p[16]={0};
	if(flag0) {Make_Sbox_Table();flag0=0;}
		if((in_len&0xf)||(keylen!=16)) return -1;
	int round=0;
	unsigned char Direction=0;
	unsigned char Subkey[800];
	Key_Schedule(key, keylen, Direction, Subkey);
	unsigned char S[4][4];
	int i,j,k=0,l,f[3],step,n;
	int CryptRound=10;
	for(int time=0;time<in_len>>4;time++)
	{
		for(i=0;i<4;i++)
			for(j=0;j<4;j++)
				S[i][j]=*(input+4*i+j+16*time)^c[4*i+j];
		Addroundkey(S,0,Subkey,in_len);
		for(round=0;round<CryptRound/2;round++)
		{
			for(i=0;i<4;i++)
				for(step=0;step<4;step++)
				{
					f[0]=S[i][0];f[1]=S[i][1];f[2]=S[i][2];
					S[i][0]=Sbox0[(S[i][2]^S[i][3])][S[i][0]];
					S[i][1]=Sbox1[(f[0]^S[i][3])][S[i][1]];
					S[i][2]=Sbox2[(f[0]^f[1])][S[i][2]];
					S[i][3]=Sbox3[(f[2]^f[1])][S[i][3]];
				}
			for(i=0;i<4;i++)	
				for(j=0;j<4;j++)
					S[i][j]=S[i][j]^*(Subkey+(j<<2)+i+(2*round+1)*16);
			for(i=0;i<4;i++)
				for(step=0;step<4;step++)
				{
					f[0]=S[0][i];f[1]=S[1][i];f[2]=S[2][i];
					S[0][i]=Sbox0[(S[2][i]^S[3][i])][S[0][i]];
					S[1][i]=Sbox1[(f[0]^S[3][i])][S[1][i]];
					S[2][i]=Sbox2[(f[0]^f[1])][S[2][i]];
					S[3][i]=Sbox3[(f[2]^f[1])][S[3][i]];
				}
			if(round==CryptRound/2-1)
				P_Layer(S,in_len);
			for(i=0;i<4;i++)	
				for(j=0;j<4;j++)
					S[i][j]=S[i][j]^*(Subkey+(i<<2)+j+2*(round+1)*16);
		}
	L_layer(S,in_len);
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			c[4*i+j]=S[i][j];

		for(int h=0;h<16;h++)
			output[s2++]=c[h];
	}
	*(out_len)=s2;
	printf("\n");
	return 0;
}

int Crypt_Dec_Block_CBC( unsigned char * input, int in_len, unsigned char * output, int * out_len, unsigned char * key, int keylen )
{
	int s1=0,s2=0;
	if(flag0) {Make_Sbox_Table();flag0=0;}
	if((in_len&0xf)||(keylen!=16)) return -1;
	int round=0;
	unsigned char Direction=1;
	unsigned char Subkey[800];
	Key_Schedule(key, keylen, Direction, Subkey);
	unsigned char S[4][4];
	int i,j,k=0,l,f[3],step,n;
	int CryptRound=10;
	unsigned char c[16]={0},p[16]={0},iv[16]={0};

	for(n=0;n<(in_len>>4);n++)
	{
		for(i=0;i<4;i++)
			for(j=0;j<4;j++)
				S[i][j]=*(input+4*i+j+16*n);

		round=0;
		Addroundkey(S,round++,Subkey,in_len);
		for(round;round<CryptRound;round++)
		{
			for(i=0;i<4;i++)
				inv_S_Box_32bit(S[i]);
			Addroundkey(S,round,Subkey,in_len);
			P_Layer(S,in_len);
		}
		for(i=0;i<4;i++)
			inv_S_Box_32bit(S[i]);
		Addroundkey(S,round,Subkey,in_len);
		L_layer(S,in_len);

	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
		{	
			output[s2++]=S[i][j]^iv[4*i+j];
			iv[4*i+j]=*(input+4*i+j+16*n);
		}
	}
	*(out_len)=s2;
	printf("\n");
	return 0;
}