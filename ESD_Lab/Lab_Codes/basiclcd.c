#include <lpc17xx.h>
#include <stdlib.h> // For rand() and srand()
#include <time.h>   // For seeding random numbers
#include <string.h>
#define RS_CTRL 0x08000000 // P0.27, 1<<27
#define EN_CTRL 0x10000000 // P0.28, 1<<28
#define DT_CTRL 0x07800000 // P0.23 to P0.26 data lines, F<<23


unsigned long int temp1 = 0, temp2 = 0, i, j, run_loop=1;
unsigned char flag1 = 0, flag2 = 0;
unsigned char msg[] = {"SEXY"};
void lcd_write(void);
void port_write(void);
void delay_lcd(unsigned int);
unsigned long int init_command[] = {0x30, 0x30, 0x30, 0x20, 0x28, 0x0c, 0x06, 0x01, 0x80};
int main(void)
{
		// srand(time(NULL));
    SystemInit();
    SystemCoreClockUpdate();
    LPC_GPIO0->FIODIR = DT_CTRL | RS_CTRL | EN_CTRL;
		
    flag1 = 0;
    for (i = 0; i < 9; i++)
    {
        temp1 = init_command[i];
        lcd_write();
    }
    flag1 = 1; // DATA MODE
    i = 0;
		
		while(1)
    {
				if(msg[i] != '\0' && run_loop){					
					temp1 = msg[i];
					lcd_write();
					i++;
				}
				
				if(msg[i] == '\0'){
					run_loop = 0;
				}
				
				
				
				if(!(LPC_GPIO2->FIOPIN & 1 << 12)){
					delay_lcd(200000);
					flag1 = 0;
					temp1 = 0x1;
					lcd_write();		
					flag1 = 1;
					i=0;
					delay_lcd(200000);
					run_loop=1;
					0.
				}
    }
    while (1){
			
				// if((LPC_GPIO2->FIOPIN & 1 << 12)){
			
					//flag1 = 0;
					//temp1 = 0x1;
					//lcd_write();
			
			/*		
					temp1 = 0x80;
					lcd_write();
				
					
					flag1 = 1;
				*/	
					// temp1 = 0x5;
					//lcd_write();
					
				//}
		}
}

void lcd_write(void)
{
    flag2 = (flag1 == 1) ? 0 : ((temp1 == 0x30) || (temp1 == 0x20)) ? 1
                                                                    : 0;
    temp2 = temp1 & 0xf0;
    temp2 = temp2 << 19;
    port_write();
    if (flag2 == 0)
    {
        temp2 = temp1 & 0x0f; // 26-4+1
        temp2 = temp2 << 23;
        port_write();
    }
}
void port_write(void)
{
    LPC_GPIO0->FIOPIN = temp2;
    if (flag1 == 0)
        LPC_GPIO0->FIOCLR = RS_CTRL;
    else
        LPC_GPIO0->FIOSET = RS_CTRL;
    LPC_GPIO0->FIOSET = EN_CTRL;
    delay_lcd(25);
    LPC_GPIO0->FIOCLR = EN_CTRL;
    delay_lcd(100000);
}
void delay_lcd(unsigned int r1)
{
    unsigned int r;
    for (r = 0; r < r1; r++)
        ;
    return;
}
