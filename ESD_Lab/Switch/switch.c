	#include <LPC17xx.h>

	unsigned long LED = 0xFF << 4; // LED on P0.4 to P0.11

	int main(void) {
			// Initialize system
			SystemInit();
			SystemCoreClockUpdate();

			// Configure Port0 PINS P0.4-P0.11 as GPIO output
			LPC_PINCON->PINSEL0 &= 0xFF0000FF; // Clear the mode bits for P0.4 to P0.11
			LPC_GPIO0->FIODIRL |= 0x0FF0; // Set P0.4 to P0.11 as output

			// Configure Port2 PIN 12 as GPIO input
			LPC_PINCON->PINSEL4 &= ~(0x3 << 24); // Clear the mode bits for P2.12
			LPC_GPIO2->FIODIR &= ~(1 << 12); // Set P2.12 as input

			while (1) {
					// Check the state of the switch connected to P2.12
					if (LPC_GPIO2->FIOPIN & (1 << 12)) {
							// Switch is released (high)
							LPC_GPIO0->FIOCLRL = LED; // Turn off LED
					} else {
							// Switch is pressed (low)
							LPC_GPIO0->FIOSETL = LED; // Turn on LED
					}
			}
	}
