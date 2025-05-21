#include <stdio.h>

unsigned int i, j, k;
unsigned long LED = 0x0 << 4;
unsigned int digits[] = {0, 0, 0, 0, 0, 0, 0, 0};

int main(void)
{
    while (1)
    {

        for (j = 0; j < 500000; j++)
            ;

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
            if (digits[i] == 0)
            {
                LED = 0x0 << (4 + i); // LED = value << position
            }
            else
            {
                LED = 0x1 << (4 + i); // LED = value << position
            }
        }
        printf("%d", LED);
        for (j = 0; j < 500000; j++)
            ;
    }
}
