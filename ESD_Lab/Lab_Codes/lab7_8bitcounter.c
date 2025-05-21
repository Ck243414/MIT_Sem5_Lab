#include <LPC17xx.h>
unsigned int i, j, k;
unsigned time = 300000;
unsigned long LED = 0x0 << 4;
unsigned int digits[] = {0, 0, 0, 0, 0, 0, 0, 0};


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

    while (1)
    {
				
				delay(1);

        digits[0] += 1;

        if (digits[0] == 2)
        {
            digits[0] = 0;
            digits[1] += 1;

            if (digits[1] == 2)
            {
                digits[1] = 0;
                digits[2] += 1;

                if (digits[2] == 2)
                {
                    digits[2] = 0;
                    digits[3] += 1;

                    if (digits[3] == 2)
                    {
                        digits[3] = 0;
                        digits[4] += 1;
                    }

                    if (digits[4] == 2)
                    {
                        digits[4] = 0;
                        digits[5] += 1;

                        if (digits[5] == 2)
                        {
                            digits[5] = 0;
                            digits[6] += 1;

                            if (digits[6] == 2)
                            {
                                digits[6] = 0;
                                digits[7] += 1;

                                if (digits[7] == 2)
                                {
                                    digits[0] = 0;
                                    digits[1] = 0;
                                    digits[2] = 0;
                                    digits[3] = 0;
                                    digits[4] = 0;
                                    digits[5] = 0;
                                    digits[6] = 0;
                                    digits[7] = 0;
                                }
                            }
                        }
                    }
                }
            }
        }

        for (i = 0; i < 8; i++)
        {
          
					LED = 0x1 << (4 + i); // LED = value << position
            					
					if (digits[i] == 0)
            {
								delay(1);
								LPC_GPIO0->FIOCLRL = LED;
						}
            else
            {
								delay(1);
								LPC_GPIO0->FIOSETL = LED;
						}            
						
				}
				
				delay(1);

			}
        

 }

