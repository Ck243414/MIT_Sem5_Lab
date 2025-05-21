	AREA RESET, DATA, READONLY
	EXPORT __Vectors

__Vectors
    DCD 0x10001000      ; STACK POINTER VALUE WHEN STACK IS EMPTY
    DCD Reset_Handler   ; RESET VECTOR

	ALIGN
	AREA mycode, CODE, READONLY
ENTRY
	EXPORT Reset_Handler

Reset_Handler

	LDR R0, =HEX 		; HEX ADDRESS
	LDR R1, =ASC		; ADDRESS OF DESTINATION WHERE ASCII IS STORED

	LDRB R2, [R0] 		; LOAD 1 Byte into R2 in this case 4A	
	
	AND R3, R2, #0x0F	; MASK TO GET A
	
	CMP R3, #9			; COMPARE TO CHECK IF DIGIT IS <= 9
	BLO LESS			; IF < than 9 then branch to LESS
	ADD R3, #7			; ELSE ADD #07 to the Number
	
LESS
	ADD R3, #0x30		; ADD 30 to R3 regardless
	STRB R3, [R1]		; STORE DIGIT in ASC
	ADD R1, #4			; Increment address to store in next 4bit address space
	
	AND R4, R2, #0xF0	; MASK TO GET 4
	LSR R4, #4			; SHIFT RIGHT BY 4 BITS

	CMP R4, #9
	BLO LESS2
	
	ADD R3, #7			; ELSE ADD #07 to the Number
	
LESS2
	ADD R4, #0x30		; ADD 30 to R3 if its small
	STRB R4, [R1]		; STORE DIGIT in ASC	

STOP
	B STOP

HEX DCD 0x0000004C
	AREA DATASEG, DATA, READWRITE
ASC	DCD 0				;DST location in Data segment
	END