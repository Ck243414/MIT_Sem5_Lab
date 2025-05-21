#include <LPC17xx.h>
unsigned int i, j, counter, switch_inp = 0;
unsigned time = 300000;
unsigned long LED = 0x0 << 4;


void delay(int seconds){
	
	for (j = 0; j < time * seconds; j++)
            ;

}

int main(void)
{
    SystemInit();
    SystemCoreClockUpdate();

    LPC_PINCON->PINSEL0 &= 0xFF0000FF; // Configure  Port0 PINS  P0.4-P0.11 ;as GPIO function
		LPC_GPIO0->FIODIRL = 0x0FF0;       // Configure P0.4-P0.11 as output port

		LPC_PINCON->PINSEL4 &= ~(0x3 << 24); // Clear the mode bits for P2.12
		LPC_GPIO2->FIODIR &= ~(1 << 12); // Set P2.12 as input

    while (1)
    {	
				switch_inp = (LPC_GPIO2->FIOPIN & (1 << 12)) >> 12; // Read switch by checking the 12th bit, mask 12th bit by AND, Right shift by 12 since we want to get 1 or 0 as output;

				delay(1);
						
				if(switch_inp == 0){
						i++;
						LPC_GPIO0->FIOPIN = i << 4;
					  
				} else{
					i--;
					LPC_GPIO0->FIOPIN = i << 4;
				}
					
				delay(1);

			}
        

 }

