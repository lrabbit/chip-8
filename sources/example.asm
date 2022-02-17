; A comment line that contains nothing
label2      ADD     VE,DD           ; blah
            ADD     VE,V1           ; bluh
            ADD     I,V4            ; bleh
            CALL    label2
            AND     V3,VA
label3      CLS                     ; clear
            DRW     V2,VA,F
            DRW     V2,VA,0
            LD V4,B
            LD V5,V6
            LD I,label2
            LD VE,DT
            LD V8,K
            LD DT,V7
            LD ST,V6
            LD F,V5
            LD B,V4
            LD [I],V3
            LD V2,[I]
            LD HF,VD
            LD R,VC
            LD VA,R
            OR V2,vB
            RET
            RND V4,12
            SE V6,45
            SE V9,V5
            SHL V5
            SHL V5,V3
            SHR V8
            SHR V8,V9
            SKP VE
            SKNP VB
            SNE VD,99
            SNE VA,V0
            SUB VB,V0
            SUBN VE,VB
            SYS label2
            XOR VD,VF
            EXIT
            HIGH
            LOW
            SCU 6
            SCD 4
            SCL
            SCR

www         BYTE 0x45
            BYTE 0b10101010