;Project 3: Security Lock 

        .MODEL SMALL      ;Allows tools to make simplifying assumptions when organizing the data
        .STACK 100H       ;Reserves 256 bytes of stack space for this program
        
        .DATA             ;Data Segment
ID_DATA   DW 1234H,5678H,9876H,5432H,1991H,3AB2H,95DEH,538FH,1FFFH,0AABBH,0FF12H,0B098H,129AH,0E0F9H,0F9F9H,1A1AH,0B5B5H,0C044H,0DEF0H,0FFFFH
PASS_DATA DB 0H   ,1H   ,2H   ,3H   ,4H   ,5H   ,6H   ,7H   ,8H   ,9H    ,0AH   ,0BH   ,0CH  ,0DH   ,0EH   ,0FH  ,5H    ,0AH   ,9H    ,0DH

BUFF_ID   DB 5,?,5 DUP (?)      ;Buffer to read ID (4-Hex instead of 16-bits for simplicity in writing)
BUFF_PASS DB 2,?,2 DUP (?)      ;Buffer to read password (1-Hex instead of 4-bits for simplicity in writing)

GET_ID      DB 'Enter your ID (4-Hex): ','$'        
VAL_ID      DB '0123456789ABCDEFabcdef'
FOUR_HEX    DB 'Invalid ID: your ID number must be 4-HEX digits.','$'
INVAL_ID    DB 'Invalid ID: your ID must contain data from 0-->9 or a/A-->f/F','$'   
ID_NOTFOUND DB 'Wrong ID! Please try again.','$'
 
GET_PASS      DB 'Enter your password (1-Hex): ','$'    
PASS_NOTFOUND DB 'Wrong Password! Please try again.','$' 

CURSOR  DB 00H     
HEAD    DB 'Security Lock','$'
LINE    DB '---------------------------------------------------------------','$'
ALLOW   DB '****** ACCESS GRANTED ******','$'
;----------------------------------------------------------------------------------------------------------------  

               .CODE                      ;Code Segment
MAIN             PROC     
                 MOV  AX,@DATA            
                 MOV  DS,AX               ;Initialize DS with the address of Data Segment
                 MOV  ES,AX               ;Let DS and ES be overlapping segments
                 MOV  BP,OFFSET CURSOR    ;Move offset CURSOR to BP to use it in setting cursor position

START:           CALL SETCURSOR           ;Call SETCURSOR procedure that sets cursor position and adds a new line
                
                 ;Print the title "Security Lock"
                 MOV  AH,09H              
                 MOV  DX,OFFSET HEAD
                 INT  21H                 ;Output of a string "Security Lock" at DS:DX
                 CALL SETCURSOR                 

                 ;Get the ID as input from the user
                 MOV  AH,09H              
                 MOV  DX,OFFSET GET_ID
                 INT  21H                 ;Output of a string "Enter your ID: " at DS:DX
                 MOV  AH,0AH
                 MOV  DX,OFFSET BUFF_ID
                 INT  21H                 ;Input of a string to DS:DX (fist byte is buffer size, second byte is number of chars actually read)
                              
                 ;Check whether the entered ID is less than 4 Hex digits
                 LEA  SI,BUFF_ID+1        ;Second byte that contains the number of chars actually read
                 CMP  [SI],04H
                 JZ   VALIDATE 
                 
                 ;The ID is less than 4-HEX digits
                 CALL SETCURSOR           
                 MOV  AH,09H              
                 MOV  DX,OFFSET FOUR_HEX
                 INT  21H                 ;Output of a string "ID must be 4-Hex" at DS:DX
                 CALL DRAW_LINE
                 JMP  START               ;Access denied, jump to the begining   
                            
                 ;Check the validity of the ID in range (0-->9 , a-->f , A-->F)
VALIDATE:        MOV  AH,4                ;4-HEX digits
                 LEA  SI,BUFF_ID+2        ;Make SI points to the first byte of ID in memory
AGAIN:           LEA  DI,VAL_ID
                 MOV  CX,23               ;number of chars in VAL_ID + 1 (if the last letter 'f' is entered, CX should't be zero to be valid)
                 MOV  AL,[SI]             
                 CLD
                 REPNZ SCASB              ;Compare each HEX-bit in the ID with VAL_ID (AL - ES:DI , DI++)
                 CMP  CX,0000H
                 JZ   INVALID
                 INC  SI
                 DEC  AH
                 JNZ  AGAIN
                 JMP  VALID
                 
                 ;The ID contains invalid characters 
INVALID:         CALL SETCURSOR          
                 MOV  AH,09H              
                 MOV  DX,OFFSET INVAL_ID
                 INT  21H                 ;Output of a string "Invalid ID ..." at DS:DX
                 CALL DRAW_LINE
                 JMP  START               ;Access denied, jump to the begining 

VALID:           MOV  SI,OFFSET BUFF_ID+2 ;Initialize SI to point to the first byte of the ID in memory                
                 MOV  CX,0004H            ;4-HEX digits 
                 CALL CONVERT_STR         ;Call CONVERT_STR, converts the ID from string to its equivalent hexadecimal value
                 SUB  SI,4                ;Returns SI to point to the the begining of the first byte of ID in memory
                 MOV  AH,[SI]
                 MOV  AL,[SI+2]           
                 MOV  BH,[SI+1]
                 MOV  BL,[SI+3]           ;E.x: ID = "1234" --> AX = 0103H , BX = 0204H
                 SHL  AX,4                ;AX = 1030H
                 OR   AX,BX               ;AX = 1234H 
                 
                 ;Search for the ID whether it exists or not
                 MOV  BX,0                ;Index of the ID if found
                 MOV  CX,20               ;Set the counter to 20 decimal (20 ID entries in the database)
                 LEA  DI,ID_DATA          ;DI = OFFSET ID_DATA                                          
SEARCH:          CMP  AX,[DI]             ;Check if the ID exists or not
                 JZ   PASS                ;If found, jump to PASS
                 INC  BX
                 INC  DI
                 INC  DI                  ;DI=DI+2 (4-Hex --> word), DI points to the ID if found
                 LOOP SEARCH
                 CMP  CX,0000H         
                 JNZ  PASS                ;ID found
                 
                 ;ID not found
                 CALL SETCURSOR
                 MOV  AH,09H              
                 MOV  DX,OFFSET ID_NOTFOUND
                 INT  21H                 ;Output of a string at DS:DX
                 CALL DRAW_LINE
                 JMP  START               ;Access denied, jump to the begining                                      
                 
PASS:            CALL SETCURSOR          
          
                 ;Get the password as input from the user
                 MOV  AH,09H              
                 MOV  DX,OFFSET GET_PASS
                 INT  21H                 ;Output of a string at DS:DX
                 MOV  AH,0AH              
                 MOV  DX,OFFSET BUFF_PASS
                 INT  21H                 ;Input of a string "Enter your password: " to DS:DX                 
                 
                 MOV  SI,OFFSET BUFF_PASS+2 ;Initialize, SI to point to the first byte of the password in memory
                 MOV  CX,0001H            ;1-HEX digit (4-bits password)
                 CALL CONVERT_STR         ;Call CONVERT_STR, converts the password from string to its equivalent hexadecimal value   
                 SUB  SI,1                ;Returns SI to point to the begining of the first byte of password in memory
                 MOV  AL,[SI]
                 
                 ;Search for the password whether it exists or not
                 MOV  DX,20               ;20 entries in ID datbase
                 SUB  DX,BX               ;DX = DX-BX (to determine the ID from where we should start calculating the offset to get its pass)
                 ADD  DX,DX               ;DX = DX*2 (word) --> DX contains the ID offest
                 ADD  DX,BX               ;DX = (20-BX)*2 + BX (where BX is the password offset) --> DX contains the total offset   
                 ADD  DI,DX               ;DI = DI+DX (added the offset to DI to get the equivalent password of the found ID)
                 CMP  AL,[DI]             ;Check if the password correct or not
                 JZ   CORRECT_PASS        
                 
                 ;Password not found
                 CALL SETCURSOR
                 MOV  AH,09H              
                 MOV  DX,OFFSET PASS_NOTFOUND
                 INT  21H                 ;Output of a string at DS:DX
                 CALL DRAW_LINE
                 JMP  START               ;Access denied, jump to the begining 
                 
CORRECT_PASS:    CALL SETCURSOR
                           
                 ;If the ID and password are correct, print "ACCESS GRANTED"
                 MOV  AH,09H              
                 MOV  DX,OFFSET ALLOW
                 INT  21H                 ;Output of a string at DS:DX
                 CALL DRAW_LINE 
                 JMP  START
                  
                 MOV AH,4CH               ;Return control to the operating system (stop program)
                 INT 21H 
MAIN             ENDP        
;----------------------------------------------------------------------------------------------------------------
                                         
SETCURSOR        PROC                     ;Set cursor position
                 MOV AH,02H              
                 MOV BH,00
                 MOV DL,00
                 MOV DH,DS:[BP]   
                 INT 10H
                 ADD DS:[BP],1            ;Adds a new line
                 RET
SETCURSOR        ENDP
;----------------------------------------------------------------------------------------------------------------

DRAW_LINE        PROC                     ;Prints a line to separate each part
                 CALL SETCURSOR          
                 MOV AH,09H
                 MOV DX,OFFSET LINE
                 INT 21H                  ;Output of a string at DS:DX
                 RET
DRAW_LINE        ENDP
;----------------------------------------------------------------------------------------------------------------

CONVERT_STR      PROC                     ;Converts the ID or password from string to its equivalent hexadecimal value
                 
AGAIN2:          CMP [SI],39H             ;39H = 9
                 JBE NUMBER               ;If <= 9 --> number
                 JA  LETTER               ;else --> letter
                                 
NUMBER:          SUB [SI],30H             ;Subtracting 30H converts ascii of the number to the equivalent hexadecimal value
                 JMP NEXT
                          
LETTER:          CMP [SI],46H             ;46H = F
                 JBE CAPITAL              ;If <= F --> Capital letter
                 JA  SMALL                ;else --> small letter (allowing the user to enter small Hex-letters for simplicity)
                 
CAPITAL:         SUB [SI],37H             ;Subtracting 37H converts ascii of the capital letter to the equivalent hexadecimal value
                 JMP NEXT
                  
SMALL:           SUB [SI],57H             ;Subtracting 57H converts ascii of the small letter to the equivalent hexadecimal value
                        
NEXT:            INC SI                   ;Points to the next digit
                 DEC CX   
                 JNZ AGAIN2                     
                 RET
CONVERT_STR      ENDP
;----------------------------------------------------------------------------------------------------------------
          
                 END MAIN