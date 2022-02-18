import os
import system
import system/io
import std/streams
import std/strutils
import std/nre
import std/tables
import std/math
import std/strformat

type
    ParsedLine = tuple
        label: string
        mnemonic: string
        operands: seq[string]

type
    RegisterType = enum
        rtV
        rtI
        rtArrI
        rtK
        rtDT
        rtST
        rtF
        rtB
        rtHF
        rtR
        rtNone

type 
    Position = enum
        pFirst
        pSecond

type
    ValueType = enum
        vtBin
        vtHex
        vtNone

const instructions = @["ADD", "AND", "CALL", "CLS", "DRW", "JP", "LD", "OR", "RET", "RND", "SE", "SHL", "SHR", "SKP", "SKNP", "SNE", "SUB", "SUBN", "SYS", "XOR", "EXIT", "HIGH", "LOW", "SCU", "SCD", "SCL", "SCR", "BYTE"]

let lineRegex = re"^(?<label>[;\w]*)\s+(?<mnemonic>[;\w]*)\s*(?<operand>[\[\]\w,+-]*)?.*$"
let registerRegex = re"(?:^[vV][0-9a-fA-F]$)|(?:^[iI]$)|(?:^\[[iI]\]$)|(?:^[kK]$)|(?:^[dD][tT]$)|(?:^[sS][tT]$)|(?:^[fF]$)|(?:^[bB]$)|(?:^[hH][fF]$)|(?:^[rR]$)"
let literalRegex = re"^[0-9a-fA-F]{1,2}$"
let byteRegex = re"^(?:0x[0-9a-fA-F]{2}$)|(?:0b[01]{8}$)"

const programStart:uint16 = 0x200

proc panic(message: string): void =
    echo message
    quit(1)

proc isByte(value: string): ValueType = 
    var matched:Option[RegexMatch] = value.match(byteRegex)
    if matched.isNone:
        return vtNone

    if value.startsWith("0b"): 
        return vtBin

    return vtHex

proc isRegister(value: string): RegisterType = 
    var matched:Option[RegexMatch] = value.match(registerRegex)
    if matched.isNone:
        return rtNone

    return case value[0]:
        of 'v', 'V': rtV
        of 'i', 'I': rtI
        of '[': rtArrI
        of 'k', 'K': rtK
        of 'd', 'D': rtDT
        of 's', 'S': rtST
        of 'f', 'F': rtF
        of 'b', 'B': rtB
        of 'h', 'H': rtHF
        of 'r', 'R': rtR
        else: rtNone

proc isLiteral(value: string, nibbles: uint8): bool = 
    var matched:Option[RegexMatch] = value.match(literalRegex)

    if matched.isSome:
        let intValue = parseHexInt(value)
        if intValue > 2^(nibbles * 4):
            panic(fmt"Value ({value}, required {nibbles * 4} bits) is too big")

    return matched.isSome

proc isSymbol(symbols: Table[string, uint16], value: string): bool = 
    return symbols.contains(value)

proc loadProgram(path: string): seq[string] = 
    var line = ""
    var program: seq[string]

    let strm:Stream = newFileStream(path, fmRead)
    if isNil(strm):
        panic("Cannot read the given file")

    while strm.readLine(line):
        if line.len == 0 or isEmptyOrWhitespace(line) or startsWith(line, ";"):
            continue

        program.add(line)

    return program

proc parseLine(line: string): ParsedLine = 
    var matched:Option[RegexMatch] = line.match(lineRegex)
    if matched.isNone:
        panic(fmt"Failed to parse line: {line}")

    let label = line.match(lineRegex).get.captures[0]
    let mnemonic = line.match(lineRegex).get.captures[1].toUpper
    let operands = line.match(lineRegex).get.captures[2]

    return (label: label, mnemonic: mnemonic, 
        operands: (if operands.contains(","): split(operands, ",") 
                    elif operands.len != 0: @[operands]
                    else: @[]))

proc extractSymbols(program: seq[string]): Table[string, uint16] =
    var symbols = initTable[string, uint16]()
    var currentPtr = programStart

    for line in program:
        # tokenize the line
        var label: string
        var mnemonic: string
        var operands: seq[string]
        (label, mnemonic, operands) = parseLine(line)

        if label.len != 0 and not label.startsWith(";"):
            if symbols.contains(label):
                panic(fmt"Symbol already used: {label}")

            if isRegister(label) != rtNone:
                panic(fmt"Invalid symbol: {label}")

            symbols[label] = currentPtr

        currentPtr = currentPtr + 2

    echo "--- symbols ---"
    for s in keys(symbols):
        echo fmt"label: {s} -> 0x{toHex(symbols[s], 4)}"

    return symbols

proc stripHead(value: string): string = 
    return value[1..^1]

proc parseOperand(operand: string, position: Position): uint16 = 
    let value = parseHexInt(stripHead(operand))
    let shift = (if position == pFirst: 8 else: 4)
    return cast[uint16](value shl shift)

proc parseLiteral(literal: string): uint16 =
    return cast[uint16](parseHexInt(literal))

proc assembleOpcode(symbols: Table[string, uint16], opcode: uint16, vx = "", vy = "", value = ""): uint16 =
    var output = opcode

    if not isEmptyOrWhitespace(vx):
        output = output + parseOperand(vx, pFirst)
    
    if not isEmptyOrWhitespace(vy):
        output = output + parseOperand(vy, pSecond)

    if not isEmptyOrWhitespace(value):
        if isLiteral(value, cast[uint8](value.len)):
            output = output + parseLiteral(value)
        else:
            if not symbols.contains(value):
                panic(fmt"Symbol not found: {value}")
            
            output = output + symbols[value]

    return output


#
# specific per-instruction assemble procedures 
#
proc assembleADD(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 7xnn - ADD Vx, byte
    # 8xy4 - ADD Vx, Vy
    # Fx1E - ADD I, Vx

    if operands.len == 2:
        if isRegister(operands[0]) == rtV:
            if isLiteral(operands[1], 2):
                return assembleOpcode(symbols, 0x7000, vx = operands[0], value = operands[1])
            elif isRegister(operands[1]) == rtV:
                return assembleOpcode(symbols, 0x8004, vx = operands[0], vy = operands[1])
        elif isRegister(operands[0]) == rtI and isRegister(operands[1]) == rtV:
            return assembleOpcode(symbols, 0xF01E, vx = operands[1])

    panic(fmt"Invalid operands for mnemonic ADD: {operands}")

proc assembleAND(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xy2 - AND Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x8002, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic AND: {operands}")

proc assembleCALL(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 2nnn - CALL addr

    if operands.len == 1 and isSymbol(symbols, operands[0]):
        return assembleOpcode(symbols, 0x2000, value = operands[0])
    
    panic(fmt"Invalid operands for mnemonic CALL: {operands}")

proc assembleCLS(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00E0 - CLS

    if operands.len == 0:
        return 0x00E0

    panic(fmt"Invalid operands for mnemonic CLS: {operands}")
 
proc assembleDRW(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # Dxyn - DRW Vx, Vy, nibble

    if operands.len == 3 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV and isLiteral(operands[2], 1):
        return assembleOpcode(symbols, 0xD000, vx = operands[0], vy = operands[1], value = operands[2])
    
    panic(fmt"Invalid operands for mnemonic DRW: {operands}")

proc assembleJP(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 1nnn - JP addr
    # Bnnn - JP V0, addr

    if operands.len == 1 and isSymbol(symbols, operands[0]):
        return assembleOpcode(symbols, 0x1000, value = operands[0])
    elif operands.len == 2 and isRegister(operands[0]) == rtV and stripHead(operands[0]) == "0" and isSymbol(symbols, operands[1]):
        return assembleOpcode(symbols, 0xB000, value = operands[1])
    
    panic(fmt"Invalid operands for mnemonic JP: {operands}")

proc assembleLD(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 6xnn - LD Vx, byte
    # 8xy0 - LD Vx, Vy
    # Annn - LD I, addr
    # Fx07 - LD Vx, DT
    # Fx0A - LD Vx, K
    # Fx15 - LD DT, Vx
    # Fx18 - LD ST, Vx
    # Fx29 - LD F, Vx
    # Fx33 - LD B, Vx
    # Fx55 - LD [I], Vx
    # Fx65 - LD Vx, [I]
    # Fx30 - LD HF, Vx
    # Fx75 - LD R, Vx
    # Fx85 - LD Vx, R

    if operands.len == 2:
        if isRegister(operands[0]) == rtV:
            if isLiteral(operands[1], 2):
                return assembleOpcode(symbols, 0x6000, vx = operands[0], value = operands[1])
            elif isRegister(operands[1]) == rtV: 
                return assembleOpcode(symbols, 0x8000, vx = operands[0], vy = operands[1])
            elif isRegister(operands[1]) == rtDT: 
                return assembleOpcode(symbols, 0xF007, vx = operands[0])
            elif isRegister(operands[1]) == rtK: 
                return assembleOpcode(symbols, 0xF00A, vx = operands[0])
            elif isRegister(operands[1]) == rtArrI: 
                return assembleOpcode(symbols, 0xF065, vx = operands[0])
            elif isRegister(operands[1]) == rtR: 
                return assembleOpcode(symbols, 0xF085, vx = operands[0])
        elif isRegister(operands[1]) == rtV:
            if isRegister(operands[0]) == rtDT:
                return assembleOpcode(symbols, 0xF015, vx = operands[1])
            elif isRegister(operands[0]) == rtST:
                return assembleOpcode(symbols, 0xF018, vx = operands[1])
            elif isRegister(operands[0]) == rtF:
                return assembleOpcode(symbols, 0xF029, vx = operands[1])
            elif isRegister(operands[0]) == rtB:
                return assembleOpcode(symbols, 0xF033, vx = operands[1])
            elif isRegister(operands[0]) == rtArrI:
                return assembleOpcode(symbols, 0xF055, vx = operands[1])
            elif isRegister(operands[0]) == rtHF:
                return assembleOpcode(symbols, 0xF030, vx = operands[1])
            elif isRegister(operands[0]) == rtR:
                return assembleOpcode(symbols, 0xF075, vx = operands[1])
        elif isRegister(operands[0]) == rtI and isSymbol(symbols, operands[1]):
            return assembleOpcode(symbols, 0xA000, value = operands[1])
        
    panic(fmt"Invalid operands for mnemonic LD: {operands}")

proc assembleOR(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xy1 - OR Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x8001, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic OR: {operands}")

proc assembleRET(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00EE - RET

    if operands.len == 0:
        return 0x00EE

    panic(fmt"Invalid operands for mnemonic RET: {operands}")

proc assembleRND(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # Cxnn - RND Vx, byte

    if operands.len == 2 and isRegister(operands[0]) == rtV and isLiteral(operands[1], 2):
        return assembleOpcode(symbols, 0xC000, vx = operands[0], value = operands[1])
    
    panic(fmt"Invalid operands for mnemonic RND: {operands}")

proc assembleSE(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 3xnn - SE Vx, byte
    # 5xy0 - SE Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV:
        if isLiteral(operands[1], 2):
            return assembleOpcode(symbols, 0x3000, vx = operands[0], value = operands[1])
        elif isRegister(operands[1]) == rtV:
            return assembleOpcode(symbols, 0x5000, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic SE: {operands}")

proc assembleSHL(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xyE - SHL Vx {, Vy}

    if operands.len == 1 and isRegister(operands[0]) == rtV:
        return assembleOpcode(symbols, 0x800E, vx = operands[0])
    elif operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x800E, vx = operands[0], vy = operands[1])

    panic(fmt"Invalid operands for mnemonic SHL: {operands}")

proc assembleSHR(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xy6 - SHR Vx {, Vy}

    if operands.len == 1 and isRegister(operands[0]) == rtV:
        return assembleOpcode(symbols, 0x8006, vx = operands[0])
    elif operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x8006, vx = operands[0], vy = operands[1])

    panic(fmt"Invalid operands for mnemonic SHR: {operands}")

proc assembleSKP(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # Ex9E - SKP Vx

    if operands.len == 1 and isRegister(operands[0]) == rtV:
        return assembleOpcode(symbols, 0xE09E, vx = operands[0])
    
    panic(fmt"Invalid operands for mnemonic SKP: {operands}")

proc assembleSKNP(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # ExA1 - SKNP Vx

    if operands.len == 1 and isRegister(operands[0]) == rtV:
        return assembleOpcode(symbols, 0xE0A1, vx = operands[0])
    
    panic(fmt"Invalid operands for mnemonic SKNP: {operands}")

proc assembleSNE(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 4xnn - SNE Vx, byte
    # 9xy0 - SNE Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV:
        if isLiteral(operands[1], 2):
            return assembleOpcode(symbols, 0x4000, vx = operands[0], value = operands[1])
        elif isRegister(operands[1]) == rtV:
            return assembleOpcode(symbols, 0x9000, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic SNE: {operands}")

proc assembleSUB(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xy5 - SUB Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x8005, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic SUB: {operands}")

proc assembleSUBN(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xy7 - SUBN Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x8007, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic SUBN: {operands}")

proc assembleSYS(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 0nnn - SYS addr

    if operands.len == 1 and isSymbol(symbols, operands[0]):
        return assembleOpcode(symbols, 0x0000, value = operands[0])
    
    panic(fmt"Invalid operands for mnemonic SYS: {operands}")


proc assembleXOR(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 8xy3 - XOR Vx, Vy

    if operands.len == 2 and isRegister(operands[0]) == rtV and isRegister(operands[1]) == rtV:
        return assembleOpcode(symbols, 0x8003, vx = operands[0], vy = operands[1])
    
    panic(fmt"Invalid operands for mnemonic XOR: {operands}")

proc assembleEXIT(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00FD - EXIT

    if operands.len == 0:
        return 0x00FD
    
    panic(fmt"Invalid operands for mnemonic EXIT: {operands}")

proc assembleHIGH(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00FF - HIGH

    if operands.len == 0:
        return 0x00FF
    
    panic(fmt"Invalid operands for mnemonic HIGH: {operands}")

proc assembleLOW(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00FE - LOW

    if operands.len == 0:
        return 0x00FE
    
    panic(fmt"Invalid operands for mnemonic LOW: {operands}")

proc assembleSCU(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00Bn - SCU nibble

    if operands.len == 1 and isLiteral(operands[0], 1):
        return assembleOpcode(symbols, 0x00B0, value = operands[0])
    
    panic(fmt"Invalid operands for mnemonic SCU: {operands}")

proc assembleSCD(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00Cn - SCD nibble

    if operands.len == 1 and isLiteral(operands[0], 1):
        return assembleOpcode(symbols, 0x00C0, value = operands[0])
    
    panic(fmt"Invalid operands for mnemonic SCD: {operands}")

proc assembleSCL(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00FC - SCL

    if operands.len == 0:
        return 0x00FC
    
    panic(fmt"Invalid operands for mnemonic SCL: {operands}")

proc assembleSCR(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # 00FB - SCR

    if operands.len == 0:
        return 0x00FB
    
    panic(fmt"Invalid operands for mnemonic SCR: {operands}")

proc assembleBYTE(symbols: Table[string, uint16], operands: seq[string]): uint16 = 
    # BYTE 0b00001111
    # BYTE 0x0F

    if operands.len == 1:
        if isByte(operands[0]) == vtBin:
            return cast[uint16](parseBinInt(operands[0]))
        elif isByte(operands[0]) == vtHex:
            return cast[uint16](parseHexInt(operands[0]))

    panic(fmt"Invalid operands for directive BYTE: {operands}")

proc assemble(program: seq[string], symbols: Table[string, uint16]): seq[uint16] = 
    var currentPtr = programStart
    var assembled = newSeq[uint16]()
    var dump = newSeq[string]()

    for line in program:
        # tokenize the line
        var label: string
        var mnemonic: string
        var operands: seq[string]
        (label, mnemonic, operands) = parseLine(line)

        if label.startsWith(";") or mnemonic.startsWith(";"):
            continue

        if not instructions.contains(mnemonic):
            panic(fmt"Invalid instruction: {mnemonic}")

        let opcode = case mnemonic:
            of "ADD": assembleADD(symbols, operands)
            of "AND": assembleAND(symbols, operands)
            of "CALL": assembleCALL(symbols, operands)
            of "CLS": assembleCLS(symbols, operands)
            of "DRW": assembleDRW(symbols, operands)
            of "JP": assembleJP(symbols, operands)
            of "LD": assembleLD(symbols, operands)
            of "OR": assembleOR(symbols, operands)
            of "RET": assembleRET(symbols, operands)
            of "RND": assembleRND(symbols, operands)
            of "SE": assembleSE(symbols, operands)
            of "SHL": assembleSHL(symbols, operands)
            of "SHR": assembleSHR(symbols, operands)
            of "SKP": assembleSKP(symbols, operands)
            of "SKNP": assembleSKNP(symbols, operands)
            of "SNE": assembleSNE(symbols, operands)
            of "SUB": assembleSUB(symbols, operands)
            of "SUBN": assembleSUBN(symbols, operands)
            of "SYS": assembleSYS(symbols, operands)
            of "XOR": assembleXOR(symbols, operands)

            # super chip-48
            of "EXIT": assembleEXIT(symbols, operands)
            of "HIGH": assembleHIGH(symbols, operands)
            of "LOW": assembleLOW(symbols, operands)
            of "SCU": assembleSCU(symbols, operands)
            of "SCD": assembleSCD(symbols, operands)
            of "SCL": assembleSCL(symbols, operands)
            of "SCR": assembleSCR(symbols, operands)

            # directives
            of "BYTE": assembleBYTE(symbols, operands)

            else: 0

        assembled.add(opcode)
        dump.add(fmt"0x{toHex(currentPtr, 3)}  {toHex(opcode, 4)}          {line}")

        currentPtr = currentPtr + 2
    
    echo ""
    echo "--- assembled statements ---"
    for d in dump:
        echo d

    return assembled

proc writeProgram(assembled: seq[uint16], outputFile: string): void = 
    let outFile = open(outputFile, fmWrite)

    for opcode in assembled:
        write(outFile, chr((opcode and 0xFF00'u16) shr 8))
        write(outFile, chr(opcode and 0x00FF'u16))

    close(outFile)


if paramCount() < 1:
    echo "usage: asm <input file> [<output file>]"
    quit(1)

# load program
let program = loadProgram(paramStr(1))

# extract symbols
let symbols = extractSymbols(program)

# assemble the program
let assembled = assemble(program, symbols)

# write the output
if paramCount() == 2:
    writeProgram(assembled, paramStr(2))