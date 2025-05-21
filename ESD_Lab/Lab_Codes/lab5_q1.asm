	AREA RESET, DATA, READONLY
	EXPORT __Vectors
__Vectors
	DCD 0x10001000
	DCD Reset_Handler
	ALIGN
	AREA mycode, CODE, READONLY
	ENTRY
	EXPORT Reset_Handler
	
Reset_Handler
	LDR R0, =LIST 	; Get input list address
	LDR R1, =RES 	; Get result list address
	MOV R2, #0
	MOV R3, #10
UP
	LDR R4, [R0, R2] ; Load data from list
	STR R4, [R1, R2] ; store data in result
	ADD R2, #4		 ; Add 4 bits to R2 for next address
	SUB R3, #1		 ; Decrement number of loops run
	CMP R3, #0
	BHI UP
	
	LDR R0, =RES
	
	MOV R4, #10		; Inner Loop Counter
	SUB R4, R4, #1	
	MOV R9, R4		
	
OUTER_LOOP
	MOV R5, R0
	MOV R2, R4

	
LIST DCD 0x1, 0x5, 0x4, 0x8, 0x3, 0x2, 0x9, 0x7, 0x11, 0x06 
	AREA data, DATA, READWRITE
RES DCW 0,0,0,0,0,0,0,0,0,0
	END