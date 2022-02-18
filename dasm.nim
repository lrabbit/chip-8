import os
import system/io
import std/strformat
import std/strutils
import std/tables

const programStart: uint16 = 0x200

type 
    Position = enum
        pFirst
        pSecond

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

proc isAddress(opcode: uint16): bool = 
    return (opcode and 0x0FFF'u16) >= programStart

proc getLabel(symbols: ref Table[uint16, string], opcode: uint16): string = 
    let address = opcode and 0x0FFF'u16
    if symbols.contains(address):
        return symbols[address]

    let label = "label" & $symbols.len
    symbols[address] = label

    return label

proc getRegister(opcode: uint16, position: Position): string =
    let shift = (if position == pFirst: 8 else: 4)
    let mask = (if position == pFirst: 0x0F00'u16 else: 0x00F0'u16)
    return fmt"V{toHex(((opcode and mask) shr shift), 1)}"

proc isRegister(opcode: uint16, position: Position): bool =
    let shift = (if position == pFirst: 8 else: 4)
    let mask = (if position == pFirst: 0x0F00'u16 else: 0x00F0'u16)
    let value = (opcode and mask) shr shift
    return value >= 0x0 and value <= 0xF

proc getValue(opcode: uint16, size: int): string = 
    if size > 2:
        panic("Size cannot be greater than 2")

    let mask = (if size == 1: 0x000F'u16 else: 0x00FF'u16)
    return toHex(opcode and mask, size)

proc formatInstruction(mnemonic:string, vx = "", vy = "", value = ""): string = 
    let hasVx = not isEmptyOrWhitespace(vx)
    let hasVy = not isEmptyOrWhitespace(vy)
    let hasValue = not isEmptyOrWhitespace(value)

    if hasVx or hasVy or hasValue:
        var instruction = alignLeft(mnemonic, 8)
        
        if hasVx:
            instruction = instruction & fmt"{vx}"
        
        if hasVy:
            instruction = instruction & (if hasVx: "," else: "") & fmt"{vy}"

        if hasValue:
            instruction = instruction & (if hasVx or hasVy: "," else: "") & value

        return instruction

    else:
        return mnemonic

proc disassembleBYTE(opcode: uint16): string = 
    return formatInstruction("BYTE", value = fmt"0x{toHex(opcode, 4)}")

proc disassemble0(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
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
    elif isAddress(opcode):
        return formatInstruction("SYS", value = getLabel(symbols, opcode))
    elif (opcode and 0xFFF0) == 0x00B0:
        return formatInstruction("SCU", value = toHex(opcode and 0x000F, 1))
    elif (opcode and 0xFFF0) == 0x00C0:
        return formatInstruction("SCD", value = toHex(opcode and 0x000F, 1))
    
    return disassembleBYTE(opcode)

proc disassemble1(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 1nnn - JP addr

    if isAddress(opcode):
        return formatInstruction("JP", value = getLabel(symbols, opcode))

    return disassembleBYTE(opcode)

proc disassemble2(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 2nnn - CALL addr

    if isAddress(opcode):
        return formatInstruction("CALL", value = getLabel(symbols, opcode))

    return disassembleBYTE(opcode)

proc disassemble3(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 3xnn - SE Vx, byte

    if isRegister(opcode, pFirst):
        return formatInstruction("SE", vx = getRegister(opcode, pFirst) , value = getValue(opcode, 2))

    return disassembleBYTE(opcode)

proc disassemble4(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 4xnn - SNE Vx, byte

    if isRegister(opcode, pFirst):
        return formatInstruction("SNE", vx = getRegister(opcode, pFirst), value = getValue(opcode, 2))

    return disassembleBYTE(opcode)

proc disassemble5(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 5xy0 - SE Vx, Vy

    if (opcode and 0xF00F) == 0x5000 and isRegister(opcode, pFirst) and isRegister(opcode, pSecond):
        return formatInstruction("SE", vx = getRegister(opcode, pFirst), vy =getRegister(opcode, pSecond))

    return disassembleBYTE(opcode)

proc disassemble6(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 6xnn - LD Vx, byte

    if isRegister(opcode, pFirst):
        return formatInstruction("LD", vx = getRegister(opcode, pFirst), value = getValue(opcode, 2))

    return disassembleBYTE(opcode)

proc disassemble7(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 7xnn - ADD Vx, byte

    if isRegister(opcode, pFirst):
        return formatInstruction("ADD", vx = getRegister(opcode, pFirst), value = getValue(opcode, 2))

    return disassembleBYTE(opcode)

proc disassemble8(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 8xy0 - LD Vx, Vy
    # 8xy1 - OR Vx, Vy
    # 8xy2 - AND Vx, Vy
    # 8xy3 - XOR Vx, Vy
    # 8xy4 - ADD Vx, Vy
    # 8xy5 - SUB Vx, Vy
    # 8xy6 - SHR Vx {, Vy}
    # 8xy7 - SUBN Vx, Vy
    # 8xyE - SHL Vx {, Vy}

    if isRegister(opcode, pFirst) and isRegister(opcode, pSecond):
        if (opcode and 0xF00F) == 0x8000:
            return formatInstruction("LD", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8001:
            return formatInstruction("OR", vx =getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8002:
            return formatInstruction("AND", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8003:
            return formatInstruction("XOR", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8004:
            return formatInstruction("ADD", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8005:
            return formatInstruction("SUB", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8006:
            if getRegister(opcode, pSecond) == "0":
                return formatInstruction("SHR", vx = getRegister(opcode, pFirst))
            else:
                return formatInstruction("SHR", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x8007:
            return formatInstruction("SUBN", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))
        elif (opcode and 0xF00F) == 0x800E:
            if getRegister(opcode, pSecond) == "0":
                return formatInstruction("SHL", vx = getRegister(opcode, pFirst))
            else:
                return formatInstruction("SHL", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))

    return disassembleBYTE(opcode)

proc disassemble9(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # 9xy0 - SNE Vx, Vy

    if (opcode and 0xF00F) == 0x9000 and isRegister(opcode, pFirst) and isRegister(opcode, pSecond):
        return formatInstruction("SNE", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond))

    return disassembleBYTE(opcode)

proc disassembleA(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # Annn - LD I, addr

    if isAddress(opcode):
        return formatInstruction("LD", vx = "I", value = getLabel(symbols, opcode))

    return disassembleBYTE(opcode)

proc disassembleB(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # Bnnn - JP V0, addr

    if isAddress(opcode):
        return formatInstruction("JP", vx = "V0", value = getLabel(symbols, opcode))

    return disassembleBYTE(opcode)

proc disassembleC(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # Cxkk - RND Vx, byte

    if isRegister(opcode, pFirst):
        return formatInstruction("RND", vx = getRegister(opcode, pFirst), value = getValue(opcode, 2))

    return disassembleBYTE(opcode)

proc disassembleD(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # Dxyn - DRW Vx, Vy, nibble

    if isRegister(opcode, pFirst) and isRegister(opcode, pSecond):
        return formatInstruction("DRW", vx = getRegister(opcode, pFirst), vy = getRegister(opcode, pSecond), value = getValue(opcode, 1))

    return disassembleBYTE(opcode)

proc disassembleE(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # Ex9E - SKP Vx
    # ExA1 - SKNP Vx

    if isRegister(opcode, pFirst):
        if (opcode and 0xF0FF) == 0xE09E:
            return formatInstruction("SKP", vx = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xE0A1:
            return formatInstruction("SKNP", vx = getRegister(opcode, pFirst))

    return disassembleBYTE(opcode)

proc disassembleF(symbols: ref Table[uint16, string], opcode: uint16, currentPtr: uint16): string = 
    # Fx07 - LD Vx, DT
    # Fx0A - LD Vx, K
    # Fx15 - LD DT, Vx
    # Fx18 - LD ST, Vx
    # Fx1E - ADD I, Vx
    # Fx29 - LD F, Vx
    # Fx33 - LD B, Vx
    # Fx55 - LD [I], Vx
    # Fx65 - LD Vx, [I]
    # Fx30 - LD HF, Vx
    # Fx75 - LD R, Vx
    # Fx85 - LD Vx, R
    # Fx1E - ADD I, Vx

    if isRegister(opcode, pFirst):
        if (opcode and 0xF0FF) == 0xF007:
            return formatInstruction("LD", vx = getRegister(opcode, pFirst), vy = "DT")
        elif (opcode and 0xF0FF) == 0xF00A:
            return formatInstruction("LD", vx = getRegister(opcode, pFirst), vy = "K")
        elif (opcode and 0xF0FF) == 0xF065:
            return formatInstruction("LD", vx = getRegister(opcode, pFirst), vy = "[I]")
        elif (opcode and 0xF0FF) == 0xF085:
            return formatInstruction("LD", vx = getRegister(opcode, pFirst), vy = "R")
        elif (opcode and 0xF0FF) == 0xF01E:
            return formatInstruction("ADD", vx = "I", vy = getRegister(opcode, pFirst))
        if (opcode and 0xF0FF) == 0xF015:
            return formatInstruction("LD", vx = "DT", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF018:
            return formatInstruction("LD", vx = "ST", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF01E:
            return formatInstruction("LD", vx = "I", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF029:
            return formatInstruction("LD", vx = "F", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF033:
            return formatInstruction("LD", vx = "B", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF055:
            return formatInstruction("LD", vx = "[I]", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF030:
            return formatInstruction("LD", vx = "HF", vy = getRegister(opcode, pFirst))
        elif (opcode and 0xF0FF) == 0xF075:
            return formatInstruction("LD", vx = "R", vy = getRegister(opcode, pFirst))

    return disassembleBYTE(opcode)

proc disassemble(opcodes: seq[uint16]): (TableRef[uint16, string], seq[string]) =
    var symbols = newTable[uint16, string]()
    var instructions = newSeq[string]()
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

        if instruction == "":
            continue

        instructions.add(instruction)

        currentPtr = currentPtr + 2
    
    return (symbols, instructions)


if paramCount() < 1:
    echo "usage: dasm <input file> [<output file>]"
    quit(1)

let opcodes = readProgram(paramStr(1))

var symbols: TableRef[uint16, string]
var instructions: seq[string]

(symbols, instructions) = disassemble(opcodes)

var currPtr = programStart

for instruction in instructions:
    let label = alignLeft((if symbols.contains(currPtr): symbols[currPtr] else: ""), 10)
    echo fmt"{label}{instruction}"

    currPtr = currPtr + 2

