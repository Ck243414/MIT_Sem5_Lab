	AREA RESET,DATA,READONLY
	EXPORT __Vectors
__Vectors
	DCD 0X10000000
    DCD Reset_Handler
    ALIGN
    AREA mycode,CODE,READONLY
	ENTRY
    EXPORT Reset_Handler
Reset_Handler
        LDR r0,=N
        LDR r1, [r0]  ; Load the value from src into r1
        MOV r2, r1
        LSR r2, #4     ; Right shift to get the higher nibble
        AND r1, #0xF    ; Mask to get the lower nibble
        MOV r3, #0xA    ; Set r3 to 10 for decimal conversion
        MLA r4, r2, r3, r1 ; Multiply higher nibble by 10 and add lower nibble
        LDR r5, =DST
        STR r4, [r5]  ; Store the result in dst
STOP
        B STOP
N DCD 0x12
        AREA mydata, DATA, READWRITE ;
DST DCD 0
        END