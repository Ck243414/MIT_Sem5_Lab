#define RS_CTRL 0x08000000 // P0.27, 1<<27
#define EN_CTRL 0x10000000 // P0.28, 1<<28
#define DT_CTRL 0x07800000 // P0.23 to P0.26 data lines, F<<23
unsigned long int temp1 = 0, temp2 = 0, i, j;
unsigned char flag1 = 0, flag2 = 0;
void lcd_write(void);
void port_write(void);
void delay_lcd(unsigned int);
unsigned char msg[] = {"MIT manipal"};
unsigned long int init_command[] = {0x30, 0x30, 0x30, 0x20, 0x28, 0x0c, 0x06, 0x01, 0x80};
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
    delay_lcd(25000);
    LPC_GPIO0->FIOCLR = EN_CTRL;
    delay_lcd(300000);
}

void delay_lcd(unsigned int r1)
{
    unsigned int r;
    for (r = 0; r < r1; r++)
        ;
    return;
}

void lcd_init(void)
{
    LPC_GPIO0->FIODIR = DT_CTRL | RS_CTRL | EN_CTRL;
    flag1 = 0;
    for (i = 0; i < 9; i++)
    {
        temp1 = init_command[i];
        lcd_write();
    }
    flag1 = 1; // DATA MODE
               /*
           i = 0;
           while (msg[i] != '\0')
           {
               temp1 = msg[i];
               lcd_write();
               i += 1;
           }*/
}

void lcd_puts(const char *str)
{
    flag1 = 1; // Data mode
    while (*str)
    {                   // Loop until the end of the string
        temp1 = *str++; // Get the next character from the string
        lcd_write();    // Write the character to the LCD
    }
}

void lcd_com(void)
{
    flag1 = 0; // Set flag1 to indicate command mode
    // Optionally, set a delay to allow the LCD to process the previous command
    delay_lcd(10000); // Delay can vary depending on the command
    lcd_write();
}
