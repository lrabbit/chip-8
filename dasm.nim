import os
import system/io
import std/strformat
import std/strutils
import std/tables

const programStart: uint16 = 0x200

proc panic(message: string): void =
    echo message
    quit(1)

proc readProgram(inputFile: string): seq[uint16] =
    let input = open(inputFile, fmRead)
    var opcodes = newSeq[uint16]()

    while not endOfFile(input):
        var opcode: uint16 = cast[uint16](readChar(input))
        if not endOfFile(input):
            opcode = (opcode shl 8) + cast[uint16](readChar(input))

        opcodes.add(opcode)

    close(input)

    return opcodes

proc disassemble0(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    # 00E0 - CLS
    # 00EE - RET
    # 0nnn - SYS addr
    # 00Bn - SCU nibble
    # 00Cn - SCD nibble
    # 00FB - SCR
    # 00FC - SCL
    # 00FD - EXIT
    # 00FE - LOW
    # 00FF - HIGH

    if opcode == 0x00E0:
        return "CLS"
    elif opcode == 0x00EE:
        return "RET"
    elif opcode == 0x00FB:
        return "SCR"
    elif opcode == 0x00FC:
        return "SCL"
    elif opcode == 0x00FD:
        return "EXIT"
    elif opcode == 0x00FE:
        return "LOW"
    elif opcode == 0x00FF:
        return "HIGH"
    elif (opcode and 0x0FFF) >= programStart:
        let label = "label" & $symbols.len
        symbols[label] = cast[uint16](opcode and 0x0FFF)
        return fmt"SYS    {label}"
    elif (opcode and 0xFFF0) == 0x00B0:
        return fmt"SCU    {toHex(opcode and 0x000F, 1)}"
    elif (opcode and 0xFFF0) == 0x00C0:
        return fmt"SCD    {toHex(opcode and 0x000F, 1)}"
    else:
        return fmt"BYTE   0x{toHex(opcode, 4)}"

proc disassemble1(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble2(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble3(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble4(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble5(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble6(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble7(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble8(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassemble9(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassembleA(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassembleB(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassembleC(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassembleD(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassembleE(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""

proc disassembleF(symbols: ref Table[string, uint16], opcode: uint16, currentPtr: uint16): string = 
    return ""


proc disassemble(opcodes: seq[uint16]): void =
    var symbols = newTable[string, uint16]()
    var currentPtr = programStart

    for opcode in opcodes:
        let msb = (opcode and 0xF000) shr 12
        let instruction = case msb:
            of 0x0: disassemble0(symbols, opcode, currentPtr)
            of 0x1: disassemble1(symbols, opcode, currentPtr)
            of 0x2: disassemble2(symbols, opcode, currentPtr)
            of 0x3: disassemble3(symbols, opcode, currentPtr)
            of 0x4: disassemble4(symbols, opcode, currentPtr)
            of 0x5: disassemble5(symbols, opcode, currentPtr)
            of 0x6: disassemble6(symbols, opcode, currentPtr)
            of 0x7: disassemble7(symbols, opcode, currentPtr)
            of 0x8: disassemble8(symbols, opcode, currentPtr)
            of 0x9: disassemble9(symbols, opcode, currentPtr)
            of 0xA: disassembleA(symbols, opcode, currentPtr)
            of 0xB: disassembleB(symbols, opcode, currentPtr)
            of 0xC: disassembleC(symbols, opcode, currentPtr)
            of 0xD: disassembleD(symbols, opcode, currentPtr)
            of 0xE: disassembleE(symbols, opcode, currentPtr)
            of 0xF: disassembleF(symbols, opcode, currentPtr)
            
            else: ""

        echo fmt("0x{toHex(currentPtr, 3)} {toHex(opcode, 4)}    {instruction}")

        currentPtr = currentPtr + 2

if paramCount() < 1:
    echo "usage: dasm <input file> [<output file>]"
    quit(1)

let opcodes = readProgram(paramStr(1))

disassemble(opcodes)