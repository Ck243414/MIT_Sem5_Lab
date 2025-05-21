#include <lpc17xx.h>
#include <stdio.h>

#define refVtg 5
#define digitalMax 0xFFF
#define RS_CTRL  0x00000100  //P0.8
#define EN_CTRL  0x10000200  //P0.9
#define DT_CTRL  0x000000F0  //P0.4 TO P0.7

unsigned long int init_command[] = {0x30,0x30,0x30,0x20,0x28,0x0c,0x06,0x01,0x80}; // Initial commands to initialize the LCD
unsigned long int temp1 = 0, temp2 = 0, i, j, var1, var2; // Variables for storing temporary data
unsigned char flag1 = 0, flag2 = 0; // Flags for differentiating between command and data mode
unsigned char msg[] = {"Voltage:"}; // Message to be displayed on LCD
unsigned char msg2[] = {"AQI: "}; // Additional message to be displayed on LCD
unsigned long int step_pos[] = {0x2,0x1,0x8,0x4}; // Step positions for LCD write

void lcd_init(void);
void lcd_write(void);
void port_write(void);
void delay(unsigned int);
void lcd_print_msg(void);
void lcd_print_msg2(void);

int main(void) {
    unsigned int mqReading, i;
    float analogVtg;
    char analogVtgStr[14], digitalValStr[14];

    SystemInit(); // System initialization
    SystemCoreClockUpdate(); // Update system clock

    LPC_PINCON->PINSEL1 |= 1<<14; // Configure P0.23 for AD0.0
    LPC_SC->PCONP |= (1<<12); // Enable power supply for ADC

    LPC_GPIO0->FIODIR = DT_CTRL | RS_CTRL | EN_CTRL; // Configure pins as output for LCD control

    lcd_init(); // Initialize LCD
    lcd_print_msg(); // Print message on LCD
    lcd_print_msg2(); // Print additional message on LCD

    LPC_GPIO2->FIODIR = 1 << 13; // Configure P2.13 as output for controlling the fan

    while(1) {
        LPC_ADC->ADCR = (1<<0) | (1<<21) | (1<<24); // Select channel 0, power on, start conversion
        while(((mqReading = LPC_ADC->ADGDR) & 0X80000000) == 0); // Wait for conversion to complete
        mqReading = LPC_ADC->ADGDR;
        mqReading >>= 4;
        mqReading &= 0x00000FFF; // Extract ADC value
        analogVtg = (((float)mqReading * (float)refVtg))/((float)digitalMax); // Calculate analog voltage

        sprintf(analogVtgStr, "%0.3fV", analogVtg); // Convert analog voltage to string
        sprintf(digitalValStr, "%d", (mqReading / 7)); // Convert digital value to string

        temp1 = 0x89; // Set cursor position for analog voltage
        flag1 = 0;
        lcd_write();
        delay(800);
        i=0;
        flag1=1;

        while(analogVtgStr[i]!='\0') {
            temp1 = analogVtgStr[i];
            lcd_write();
            i+= 1;
        }

        temp1 = 0xC5; // Set cursor position for digital value
        flag1=0;
        lcd_write();
        delay(800);
				        i=0;
        flag1=1;
        while(digitalValStr[i]!='\0'){
            temp1 = digitalValStr[i];
            lcd_write();
            i += 1;
        }

        if(mqReading >= 490) { // If air quality index exceeds threshold, turn on fan
            LPC_GPIO2->FIOPIN = 1 << 13;
            delay(50000); // Delay for fan operation
            LPC_GPIO2->FIOCLR = 1 << 13; // Turn off fan
        }

    }
}

void lcd_init(void) {
    unsigned int x;
    flag1 = 0; // Command Mode
    for(x=0;x<9;x++) {
        temp1 = init_command[x]; // Send initialization commands to LCD
        lcd_write();
    }
    flag1 = 1; // Data Mode
}

void lcd_write(void) { // Write data or command to LCD
    flag2 = (flag1 == 1) ? 0 : ((temp1 == 0x30) || (temp1 == 0x20)) ? 1 : 0; // Check flag to determine data or command mode
    temp2 = temp1 & 0xf0; // Extract most significant 4 bits
    port_write(); // Write to LCD
    if (flag2==0) { // Write least significant 4 bits only for data other than 0x30/0x20
        temp2 = temp1 & 0x0f;
        temp2 = temp2 << 4;
        port_write();
			    }
}

void port_write(void) { // Write to LCD port
    LPC_GPIO0->FIOPIN = temp2;
    if (flag1 == 0)  
        LPC_GPIO0->FIOCLR = RS_CTRL; // Command mode
    else
        LPC_GPIO0->FIOSET = RS_CTRL; // Data mode
    LPC_GPIO0->FIOSET = EN_CTRL; // Enable LCD
    delay(25);
    LPC_GPIO0->FIOCLR = EN_CTRL; // Disable LCD
    delay(30000);
}

void delay(unsigned int r1) { // Delay function
    unsigned int r;
    for(r=0;r<r1;r++);
}

void lcd_print_msg(void) { // Print message on LCD
    unsigned int a;
    for(a = 0; msg[a] != '\0'; a++) {
        temp1 = msg[a];
        lcd_write();
    }
}

void lcd_print_msg2(void) { // Print additional message on LCD
    temp1 = 0xC0; // Set cursor position
    flag1 = 0;
    lcd_write();
    delay(800);
    i = 0;
    flag1 = 1;
    while(msg2[i]!='\0'){

        temp1 = msg2[i];
        lcd_write();
        i += 1;
    }
} 

