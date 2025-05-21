#include <LPC17xx.h>
#include <stdio.h>

#define FIRST_SEG 0xF87FFFFF
#define SECOND_SEG 0xF8FFFFFF
#define THIRD_SEG 0xF97FFFFF
#define FOURTH_SEG 0xF9FFFFFF
#define DISABLE_ALL 0xFA7FFFFF

unsigned int dig1 = 0x00, dig2 = 0x00, dig3 = 0x00, dig4 = 0x00;
unsigned int twenty_count = 0x00, dig_count = 0x00, temp1 = 0x00;
unsigned char array_dec[10] = {0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07, 0x7F, 0x6F};
unsigned char tmr0_flg = 0x00, one_sec_flg = 0x00;
unsigned long int temp2 = 0x00000000, i = 0;
unsigned int temp3 = 0x00;

void delay(void);
void display(void);

int main(void) {
    SystemInit();
    SystemCoreClockUpdate();
    
    LPC_PINCON->PINSEL0 &= 0xFF0000FF; // P0.4 to P0.11
    LPC_PINCON->PINSEL3 &= 0xFFC03FFF; // P1.23 to P1.26
		
// P0 -> 0,1
// P1 -> 2,3
// P2 -> 4,5
// P3 -> 0,1

    // GPIO data lines
    LPC_GPIO0->FIODIR |= 0x00000FF0; // P0.4 to P0.11 output
    LPC_GPIO1->FIODIR |= 0x07800000; // P1.23 to P1.26 output

    while (1) {
        
        if (dig_count == 0x05) {
            dig_count = 0x00;
        }

				
        if (one_sec_flg == 0xFF) {
            one_sec_flg = 0x00;
						
						dig_count +=1;
        } // end of one_sec if

        display();
				delay();
			
    } // end of while(1)
} // end of main

void display(void) { // To Display on 7-segments
    if (dig_count == 0x01) { // For Segment U8
        temp1 = dig1;
        LPC_GPIO1->FIOPIN = FIRST_SEG;
    } else if (dig_count == 0x02) { // For Segment U9
        temp1 = dig2;
        LPC_GPIO1->FIOPIN = SECOND_SEG;
    } else if (dig_count == 0x03) { // For Segment U10
        temp1 = dig3;
        LPC_GPIO1->FIOPIN = THIRD_SEG;
    } else if (dig_count == 0x04) { // For Segment U11
        temp1 = dig4;
        LPC_GPIO1->FIOPIN = FOURTH_SEG;
    }

    temp1 &= 0x0F;
    temp2 = array_dec[1]; // Decoding to 7-segment
    temp2 = temp2 << 4;
    LPC_GPIO0->FIOPIN = temp2; // Taking Data Lines for 7-Seg

    for (i = 0; i < 500; i++); // Short delay

    LPC_GPIO0->FIOCLR = 0x00000FF0; // Clear data lines
    // LPC_GPIO1->FIOPIN = DISABLE_ALL; // Disable all the segments (optional)
}

void delay(void) {
    unsigned int i;
    for (i = 0; i < 1000; i++); // Delay loop

    if (twenty_count == 1000) { // 1 second check
        one_sec_flg = 0xFF;
        twenty_count = 0x00;
    } else {
        twenty_count += 1;
    }
}
