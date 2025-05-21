#include <LPC17xx.h>
unsigned int i,j, k;   			
unsigned long LED = 0xFF << 4;
int count = 0;
   
int main(void)
 {
   SystemInit();
   SystemCoreClockUpdate();

   LPC_PINCON->PINSEL0 &= 0xFF0000FF; // Configure  Port0 PINS  P0.4-P0.11 ;as GPIO function
   LPC_GPIO0->FIODIRL = 0x0FF0; //Configure P0.4-P0.11 as output port 
	 

	 while(1)
	{
		LPC_GPIO0->FIOSETL = LED; 
		for(j=0;j<800000;j++); 		// a random delay
		LPC_GPIO0->FIOCLRL = LED;
		for(j=0;j<800000;j++); 		// a random delay
	}
}


