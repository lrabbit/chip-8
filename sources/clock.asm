; Just a simple stopwatch example using the delay timer.
;
; Coded by Jeffrey Massung as an example of the
; CHIP-8 assembler.
;
; Have fun!
;

                ; minute and second
                ld      v4,0
                ld      v5,0

                ; show the current time
loop            call    draw_clock

                ; wait for a full second
                ld      v0,60
                ld      dt,v0

                ; wait until 1 second has elapsed
wait            ld      v0,dt
                se      v0,0
                jp      wait

                ; erase the old time
                call    draw_clock

                ; play a tick sound
                ld      v0,1
                ld      st,v0

                ; add a second
                add     v5,1
                se      v5,60
                jp      loop

                ; add a minute
                ld      v5,0
                add     v4,1

                ; done
                jp      loop

                ; load minute
draw_clock      ld      i,time
                ld      b,v4
                ld      v2,[i]

                ; draw tens
                ld      va,12
                ld      vb,10

                ld      hf,v1
                drw     va,vb,10

                ; draw ones
                add     va,10
                ld      hf,v2
                drw     va,vb,10

                ; bcd second
                ld      i,time
                ld      b,v5
                ld      v2,[i]

                ; draw tens
                add     va,14
                ld      hf,v1
                drw     va,vb,10

                ; draw ones
                add     va,10
                ld      hf,v2
                drw     va,vb,10

                ; done
                ret

time            byte    0x00
                byte    0x00
                byte    0x00