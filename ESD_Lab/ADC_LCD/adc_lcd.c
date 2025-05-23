//works

#include<LPC17xx.h>
#include<stdio.h>
int temp1, temp2, flag1, flag2;

void port_write()
{
int i;
LPC_GPIO0->FIOPIN = temp2 << 23;

if(flag1 == 0)
LPC_GPIO0->FIOCLR = 1 << 27;
else
LPC_GPIO0->FIOSET = 1 << 27;

LPC_GPIO0->FIOSET = 1 << 28;
for(i = 0; i<50; i++);
LPC_GPIO0->FIOCLR = 1 << 28;

for(i = 0; i<30000; i++);
}

void LCD_write()
{
if((flag1 == 0) & ((temp1 == 0x30) || (temp1 == 0x20)))
flag2 = 1;
else
flag2 = 0;
//flag2 = (flag1 == 1) ? 0 :((temp1 == 0x30) || (temp1 == 0x20)) ? 1 : 0;
temp2 = temp1 >> 4;
port_write();

if(flag2 == 0)
{
temp2 = temp1 & 0xF;
port_write();
}
}
int main()
{
unsigned int adc_temp;
int i;
float in_vtg;
char vtg[7],dval[7];
char msg1[]={" ANALOG IP:"};
char msg2[]={"ADC OUTPUT:"};
  int lcd_init[] = {0x30, 0x30, 0x30, 0x20, 0x28, 0x0C, 0x01, 0x80, 0x06};
SystemInit();
SystemCoreClockUpdate();

LPC_PINCON -> PINSEL1 = 0;

LPC_GPIO0 -> FIODIR = 0xF << 23 | 1 << 27 | 1 << 28;
flag1 = 0;
for(i = 0; i<=8; i++)
{
temp1 = lcd_init[i];
LCD_write();
}
flag1 = 1;
LPC_PINCON->PINSEL3=3<<30;//p1.31 as AD0.5
LPC_SC->PCONP=(1<<12);//enable peripheral adc
LPC_SC->PCONP |= (1<<15); //Power for GPIO block
flag1=0;
temp1=0x80;
LCD_write();
flag1=1;
i=0;
while(msg1[i++]!='\0')
{
temp1=msg1[i];
LCD_write();
}
flag1=0;
temp1=0xC0;
LCD_write();
flag1=1;
i=0;
while(msg2[i++]!='\0')
{
temp1=msg2[i];
LCD_write();
}
while(1)
{
LPC_ADC->ADCR = (1<<5)|(1<<21)|(1<<24);//0x01200001; //ADC0.5, start conversion and operational
//for(i=0;i<2000;i++); //delay for conversion
while(!( LPC_ADC->ADGDR >>31 == 0));//31st bit is done bit
//wait till 'done' bit is 1, indicates conversion complete
adc_temp = LPC_ADC->ADGDR;
adc_temp >>= 4;
adc_temp &= 0x00000FFF; //12 bit ADC
in_vtg = ((float)adc_temp * 3.3/0xfff); //calculating input analog as 0.805mv is resolution
//voltage
sprintf(vtg,"%3.2fV",in_vtg);
//convert the readings into string to display on LCD
sprintf(dval,"%x",adc_temp);
flag1=0;
temp1=0x8A;
LCD_write();
flag1=1;
i=0;
while(vtg[i]!='\0')
{
temp1=vtg[i];i++;
LCD_write();
}
flag1=0;
temp1=0xCA;
LCD_write();
flag1=1;
i=0;
while(dval[i]!='\0')
{
temp1=dval[i];i++;
LCD_write();
}
for(i=0;i<7;i++)
vtg[i]=dval[i]=0;
}
}


/*
//works

//Hardware mode displaying output
////ADC CHannel 5 at P1.31
#include <LPC17xx.h>
#include <stdio.h>
#define ref_vtg 3.3000
#define full_scale 0xFFF
int temp1; //carries the 8 bit data/code
int temp2; //carries the 4 bit data/code to be operated on
int flag1; //0 for command,1 for data (RS)
int flag2; //0 for 8 bits,1 for bit MSB
//P0.28 for enable, P0.27 for RS
//P0.26 to P0.23 data lines(D7 to D4)
void port_write()
{
	int j;
	LPC_GPIO0->FIOPIN=temp2<<23;
	
	if(flag1==0)
	{
		LPC_GPIO0->FIOCLR=1<<27;
	}
	else
	{
		LPC_GPIO0->FIOSET=1<<27;
	}
	//enable LCD
	LPC_GPIO0->FIOSET=1<<28;
	for(j=0;j<20;j++);//delay
	LPC_GPIO0->FIOCLR=1<<28;
	
	for(j=0;j<300000;j++);//delay for lcd to respond //300000
	
}

void lcd_write()
{

	flag2 = (flag1 == 1) ? 0 :((temp1 == 0x30) || (temp1 == 0x20)) ? 1 : 0;
	
	
	temp2=temp1&0xF0;
	temp2=temp2>>4;
	port_write();
	if(flag2==0)
	{
		temp2=temp1&0xF;
		port_write();
	}
}


int main()
{
	int i,adc_temp;
	float in_vtg;
	char vtg[7],dval[7],msg1[]="Analog IP:",msg2[]="ADC output:";
	
	int lcd_init[]={0x30,0x30,0x30,0x20,0x28,0x0C,0x06,0x01,0x80};
	
	SystemInit();
	SystemCoreClockUpdate();
	LPC_PINCON->PINSEL1=0;	
	LPC_GPIO0->FIODIR=3<<27 | 0xF<<23;
	//adc
	LPC_SC->PCONP=1<<12; //to enable lcd
	LPC_SC->PCONP|=1<<15; //POWER FOR GPIO BLOCK
	LPC_PINCON->PINSEL3=3<<30;

//sending the command codes
	flag1=0;
	for(i=0;i<9;i++)
	{
		temp1=lcd_init[i];
		lcd_write();
	}

while(1)
{
	LPC_ADC->ADCR=1<<5|1<<21|1<<24;
	while ((LPC_ADC->ADGDR & 1<<31)==0);
	//wait till done bit is 1]
	adc_temp=LPC_ADC->ADGDR;
	adc_temp>>=4;
	adc_temp&=0x00000FFF;//12 bit adc
	
	in_vtg=(((float)adc_temp*(float)ref_vtg))/((float)full_scale);
	sprintf(vtg,"%3.2fV",in_vtg);//convert readings into string
	sprintf(dval,"%d",adc_temp); //digitial equivalent
	
	
	
	//for the data
	//first line
	flag1=1;
	for(i=0;msg1[i]!='\0';i++)
	{
		temp1=msg1[i];
		lcd_write();
	}
	//
	for(i=0;vtg[i]!='\0';i++)
	{
		temp1=vtg[i];
		lcd_write();
	}
	//2nd line
	flag1=0;
	temp1=0xC0;
	lcd_write();
	flag1=1;
	
	for(i=0;msg2[i]!='\0';i++)
	{
		temp1=msg2[i];
		lcd_write();
	}
	
	for(i=0;dval[i]!='\0';i++)
	{
		temp1=dval[i];
		lcd_write();
	}
	
	
	for(i=0;i<7;i++)
	vtg[i]=dval[i]=0;
	
}


	
}
*/


/*
#include<LPC17xx.h>
#include<stdio.h>
int temp1, temp2, flag1, flag2;

void port_write()
{
int i;
LPC_GPIO0->FIOPIN = temp2 << 23;

if(flag1 == 0)
LPC_GPIO0->FIOCLR = 1 << 27;
else
LPC_GPIO0->FIOSET = 1 << 27;

LPC_GPIO0->FIOSET = 1 << 28;
for(i = 0; i<50; i++);
LPC_GPIO0->FIOCLR = 1 << 28;

for(i = 0; i<30000; i++);
}

void LCD_write()
{
if((flag1 == 0) & ((temp1 == 0x30) || (temp1 == 0x20)))
flag2 = 1;
else
flag2 = 0;
//flag2 = (flag1 == 1) ? 0 :((temp1 == 0x30) || (temp1 == 0x20)) ? 1 : 0;
temp2 = temp1 >> 4;
port_write();

if(flag2 == 0)
{
temp2 = temp1 & 0xF;
port_write();
}
}
int main()
{
unsigned int adc_temp;
int i;
float in_vtg;
char vtg[7],dval[7];
char msg1[]={" ANALOG IP:"};
char msg2[]={"ADC OUTPUT:"};
  int lcd_init[] = {0x30, 0x30, 0x30, 0x20, 0x28, 0x0C, 0x01, 0x80, 0x06};
SystemInit();
SystemCoreClockUpdate();

LPC_PINCON -> PINSEL1 = 0;

LPC_GPIO0 -> FIODIR = 0xF << 23 | 1 << 27 | 1 << 28;
flag1 = 0;
for(i = 0; i<=8; i++)
{
temp1 = lcd_init[i];
LCD_write();
}
flag1 = 1;
LPC_PINCON->PINSEL3=3<<30;//p1.31 as AD0.5
LPC_SC->PCONP=(1<<12);//enable peripheral adc
LPC_SC->PCONP |= (1<<15); //Power for GPIO block
flag1=0;
temp1=0x80;
LCD_write();
flag1=1;
i=0;
while(msg1[i++]!='\0')
{
temp1=msg1[i];
LCD_write();
}
flag1=0;
temp1=0xC0;
LCD_write();
flag1=1;
i=0;
while(msg2[i++]!='\0')
{
temp1=msg2[i];
LCD_write();
}
while(1)
{
LPC_ADC->ADCR = (1<<5)|(1<<21)|(1<<24);//0x01200001; //ADC0.5, start conversion and operational
//for(i=0;i<2000;i++); //delay for conversion
while(!( LPC_ADC->ADGDR >>31 == 0));//31st bit is done bit
//wait till 'done' bit is 1, indicates conversion complete
adc_temp = LPC_ADC->ADGDR;
adc_temp >>= 4;
adc_temp &= 0x00000FFF; //12 bit ADC
in_vtg = ((float)adc_temp * 3.3/0xfff); //calculating input analog as 0.805mv is resolution
//voltage
sprintf(vtg,"%3.2fV",in_vtg);
//convert the readings into string to display on LCD
sprintf(dval,"%x",adc_temp);
flag1=0;
temp1=0x8A;
LCD_write();
flag1=1;
i=0;
while(vtg[i]!='\0')
{
temp1=vtg[i];i++;
LCD_write();
}
flag1=0;
temp1=0xCA;
LCD_write();
flag1=1;
i=0;
while(dval[i]!='\0')
{
temp1=dval[i];i++;
LCD_write();
}
for(i=0;i<7;i++)
vtg[i]=dval[i]=0;
}
}
*/