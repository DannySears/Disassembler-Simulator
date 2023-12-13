package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

const MAXopcodeSize = 11

// Struct to represent an instruction with its mnemonic and type
type Instruction struct {
	Mnemonic string
	Type     string
}

// Struct to represent register, memory, and PC data
type Simulator struct {
	Registers [32]int32
	Memory    []int32
	PC        int32
	Cycle     int32
	BranchT   bool
}

// Map to associate binary opcodes with their instruction mnemonics and types
var opcodeMap = map[string]Instruction{
	// 6-bit opcodes
	"000101": {"B", "B"},

	// 8-bit opcodes
	"10110100": {"CBZ", "CB"},
	"10110101": {"CBNZ", "CB"},

	// 9-bit opcodes
	"110100101": {"MOVZ", "IM"},
	"111100101": {"MOVK", "IM"},

	// 10-bit opcodes
	"1001000100": {"ADDI", "I"},
	"1101000100": {"SUBI", "I"},

	// 11-bit opcodes
	"10001010000": {"AND", "R"},
	"10001011000": {"ADD", "R"},
	"10101010000": {"ORR", "R"},
	"11001011000": {"SUB", "R"},
	"11010011010": {"LSR", "R"},
	"11010011011": {"LSL", "R"},
	"11111000000": {"STUR", "D"},
	"11111000010": {"LDUR", "D"},
	"11010011100": {"ASR", "R"},
	"11101010000": {"EOR", "R"},

	// BREAK code
	"11111110110111101111111111100111": {"BREAK", "BREAK"},
	"00000000000000000000000000000000": {"NOP", "NOP"},
}

func main() {
	// Define flags
	inputFile := flag.String("i", "", "Input file name")
	outputFile := flag.String("o", "", "Output file name")

	// Parse flags
	flag.Parse()

	// Check if both inputFile and outputFile have values
	if *inputFile == "" || *outputFile == "" {
		fmt.Println("Both input and output file names must be provided")
		os.Exit(1)
	}

	memCounter := 96
	cycleCounter := 0
	simulator := Simulator{
		Registers: [32]int32{},
		Memory:    []int32{},
		PC:        96,
		Cycle:     1,
		BranchT:   false,
	}

	// Open the input file for reading
	openfile, err := os.Open(*inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer openfile.Close()

	outFileNameWithSuffix := *outputFile + "_dis.txt"
	outFileSimNameWithSuffix := *outputFile + "_sim.txt"
	outFile, err := os.Create(outFileNameWithSuffix)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	outFileSim, err := os.Create(outFileSimNameWithSuffix)
	if err != nil {
		log.Fatal(err)
	}
	defer outFileSim.Close()

	//Find the break instruction
	var decodedLines []string
	scanSim := bufio.NewScanner(openfile)
	for scanSim.Scan() {
		line := scanSim.Text()
		decodedLine, _ := defineOpcodeSim(line, &memCounter, &simulator) // Adjust as needed
		decodedLines = append(decodedLines, decodedLine)

	}

	// Find the index of the BREAK line
	breakIndex := -1
	for i, line := range decodedLines {
		if strings.Contains(line, "BREAK") { // Adjust the condition based on how BREAK is represented
			breakIndex = i
			break
		}
	}

	if breakIndex == -1 {
		fmt.Println("BREAK instruction not found in the input file")
		os.Exit(1)
	}

	//Process data after BREAK, if any
	for i := breakIndex + 1; i < len(decodedLines); i++ {
		lineParts := strings.Split(decodedLines[i], "\t") // Split the line at the tab character
		if len(lineParts) < 1 {
			log.Fatalf("Invalid data line format: '%s'", decodedLines[i])
		}
		binaryData := strings.TrimSpace(lineParts[0])          // Trim any leading/trailing whitespace
		dataValue, err := strconv.ParseUint(binaryData, 2, 32) // Parse as unsigned 32-bit integer
		if err != nil {
			log.Fatalf("Error parsing data line '%s': %v", binaryData, err)
		}

		// Calculate the memory address
		memoryAddress := 96 + ((breakIndex + 1) * 4) + (i - (breakIndex + 1))

		// Ensure memory is initialized up to this point
		if memoryAddress >= len(simulator.Memory) {
			// Initialize memory up to this point
			simulator.Memory = append(simulator.Memory, make([]int32, memoryAddress-len(simulator.Memory)+1)...)
		}

		// Insert the data
		simulator.Memory[memoryAddress] = int32(dataValue)
	}

	//reset file pointer to 0
	_, err = openfile.Seek(0, 0)
	if err != nil {
		log.Fatal(err)
	}

	// Map to hold instruction locations and corresponding machine codes
	instructionMap := make(map[int]string)
	instructionAddress := 96

	scan2 := bufio.NewScanner(openfile)
	// Read the file line by line
	for scan2.Scan() {
		// Get the machine code from the current line
		machineCode := scan2.Text()

		// Store the machine code with its instruction address
		instructionMap[instructionAddress] = machineCode

		// Increment the instruction address by 4 for the next instruction
		instructionAddress += 4
	}

	// Check for errors during Scan
	if err := scan2.Err(); err != nil {
		log.Fatalf("error during scan: %s", err)
	}

	// Print the map to verify (optional)
	//for address, code := range instructionMap {
	//fmt.Printf("Address: %d, Code: %s\n", address, code)
	//}

	//reset file pointer to 0
	_, err = openfile.Seek(0, 0)
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(openfile)
	for scanner.Scan() {
		fullline := scanner.Text()
		result, _ := defineOpcodeSim(fullline, &memCounter, &simulator)

		// Write the result to the disassembler output file for both instructions and data
		_, err := outFile.WriteString(result + "\n")
		if err != nil {
			log.Fatal(err)
		}
		memCounter += 4

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	breakHit := true
	for breakHit {

		currentPC := simulator.PC // Store the current PC before executing the instruction
		fulllineS := instructionMap[int(simulator.PC)]

		// Execute the instruction and update the simulator state

		breakCheck, _ := defineOpcode(fulllineS, &memCounter, &simulator)

		// Display the current state after executing the instruction
		if breakHit {
			cycleCounter += 1
			simulator.displayStateUsingPC(outFileSim, breakIndex+1, decodedLines, currentPC) // Use the stored PC for display
		}

		if strings.Contains(breakCheck, "BREAK") {
			breakHit = false
			continue
		}

		// Update the PC for the next instruction
		if !simulator.BranchT {
			// Normal instruction or untaken branch
			simulator.PC += 4
		} else {
			// Branch taken, PC is already updated in the instruction logic
			simulator.BranchT = false
		}
	}
}

func defineOpcode(line string, memCounter *int, s *Simulator) (string, string) {

	line = strings.ReplaceAll(line, " ", "")
	var opcode string = ""
	var exists bool
	var inst Instruction

	// Ensure the line is long enough to contain the opcode
	if len(line) >= 6 { // Minimum opcode size is 6

		if len(line) >= 32 {
			opcode = line[:32]
			inst, exists = opcodeMap[opcode]
		}

		// Check for 11-bit opcode
		if !exists && len(line) >= 11 {
			opcode = line[:11]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 10-bit opcode
		if !exists && len(line) >= 10 {
			opcode = line[:10]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 9-bit opcode
		if !exists && len(line) >= 9 {
			opcode = line[:9]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 8-bit opcode
		if !exists && len(line) >= 8 {
			opcode = line[:8]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 6-bit opcode
		if !exists && len(line) >= 6 {
			opcode = line[:6]
			inst, exists = opcodeMap[opcode]
		}

		// Check if the opcode exists in the opcodeMap
		if exists {
			// Determine the type of instruction and extract relevant bits
			switch inst.Type {

			case "R":
				rm := extractBits(line, 11, 15)
				rn := extractBits(line, 22, 26)
				rd := extractBits(line, 27, 31)
				imm := 0
				switch inst.Mnemonic {
				case "LSR", "LSL", "ASR":
					imm = extractBits(line, 16, 21)
					s.executeRType(inst.Mnemonic, rm, rn, rd, imm)
					return fmt.Sprintf("%s %s %s %s %s \t%d \t%s \tR%d, R%d, #%d", line[:11], line[11:16], line[16:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rd, rn, imm), fmt.Sprintf("\t%d \t%s \tR%d, R%d, #%d", *memCounter, inst.Mnemonic, rd, rn, imm)
				default:
					s.executeRType(inst.Mnemonic, rm, rn, rd, imm)
					return fmt.Sprintf("%s %s %s %s %s \t%d \t%s \tR%d, R%d, R%d", line[:11], line[11:16], line[16:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rd, rn, rm), fmt.Sprintf("\t%d \t%s \tR%d, R%d, R%d", *memCounter, inst.Mnemonic, rd, rn, rm)
				}

			case "CB":
				imm := extractBits(line, 8, 26)
				rt := extractBits(line, 27, 31)
				var snum int32

				binaryImm := fmt.Sprintf("%019b", imm) // Convert imm to a 19-bit binary string
				if binaryImm[0] == '1' {               // Check if the most significant bit is 1
					// Convert from two's complement to positive binary number
					invertedBinaryImm := ""
					for _, bit := range binaryImm {
						if bit == '0' {
							invertedBinaryImm += "1"
						} else {
							invertedBinaryImm += "0"
						}
					}
					positiveBinaryImm := addBinary(invertedBinaryImm, "1")
					snum = -int32(binaryToDecimal(positiveBinaryImm))
				} else {
					snum = int32(binaryToDecimal(binaryImm))
				}

				s.executeCBType(inst.Mnemonic, rt, int(snum))
				return fmt.Sprintf("%s %s %s  \t%d \t%s \tR%d, #%d", line[:8], line[8:27], line[27:], *memCounter, inst.Mnemonic, rt, snum), fmt.Sprintf("\t%d \t%s \tR%d, #%d", *memCounter, inst.Mnemonic, rt, snum)

			case "I":
				imm := extractBits(line, 10, 21)
				rn := extractBits(line, 22, 26)
				rd := extractBits(line, 27, 31)
				negBitMask := 0x800 // figure out if 12 bit num is neg
				extendMask := 0xFFFFF000
				var simm int32
				simm = int32(imm)
				if (negBitMask & imm) > 0 { // is it?
					imm = imm | extendMask // if so extend with 1's
					imm = imm ^ 0xFFFFFFFF // 2s comp
					simm = int32(imm + 1)
					simm = simm * -1 // add neg sign
				}

				s.executeIType(inst.Mnemonic, rn, rd, int(simm))
				return fmt.Sprintf("%s %s %s %s \t%d  \t%s \tR%d, R%d, #%d", line[:10], line[10:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rd, rn, simm), fmt.Sprintf("\t%d  \t%s \tR%d, R%d, #%d", *memCounter, inst.Mnemonic, rd, rn, simm)

			case "IM":
				immlo := extractBits(line, 9, 10)
				immhi := extractBits(line, 11, 26)
				rd := extractBits(line, 27, 31)
				shiftAmount := immlo * 16
				s.executeIMType(rd, immhi, shiftAmount)
				if inst.Mnemonic == "MOVZ" {
					return fmt.Sprintf("%s %s %s %s \t%d \t%s \tR%d, %d, LSL %d", line[:9], line[9:11], line[11:27], line[27:], *memCounter, inst.Mnemonic, rd, immhi, shiftAmount), fmt.Sprintf("\t%d \t%s \tR%d, %d, LSL %d", *memCounter, inst.Mnemonic, rd, immhi, shiftAmount)
				} else if inst.Mnemonic == "MOVK" {
					return fmt.Sprintf("%s %s %s %s \t%d \t%s \tR%d, %d, LSL %d", line[:9], line[9:11], line[11:27], line[27:], *memCounter, inst.Mnemonic, rd, immhi, shiftAmount), fmt.Sprintf("\t%d \t%s \tR%d, %d, LSL %d", *memCounter, inst.Mnemonic, rd, immhi, shiftAmount)
				}

			case "D":
				imm := extractBits(line, 11, 19)
				rn := extractBits(line, 22, 26)
				rt := extractBits(line, 27, 31)
				s.executeDType(inst.Mnemonic, imm, rn, rt)
				return fmt.Sprintf("%s %s %s %s %s \t%d \t%s \tR%d, [R%d, #%d]", line[:11], line[11:20], line[20:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rt, rn, imm), fmt.Sprintf("\t%d \t%s \tR%d, [R%d, #%d]", *memCounter, inst.Mnemonic, rt, rn, imm)

			case "B":
				opcodePart := line[:6]
				rawOffset := extractBits(line, 7, 31)
				var snum int32

				binaryOffset := fmt.Sprintf("%025b", rawOffset) // Convert rawOffset to a 25-bit binary string
				if binaryOffset[0] == '1' {                     // Check if the most significant bit is 1
					// Convert from two's complement to positive binary number
					invertedBinaryOffset := ""
					for _, bit := range binaryOffset {
						if bit == '0' {
							invertedBinaryOffset += "1"
						} else {
							invertedBinaryOffset += "0"
						}
					}
					positiveBinaryOffset := addBinary(invertedBinaryOffset, "1")
					snum = -int32(binaryToDecimal(positiveBinaryOffset))
				} else {
					snum = int32(binaryToDecimal(binaryOffset))
				}

				s.executeBType(int(snum))

				return fmt.Sprintf("%s %s   \t%d \t%s   \t#%d", opcodePart, line[6:], *memCounter, inst.Mnemonic, snum), fmt.Sprintf("\t%d \t%s   \t#%d", *memCounter, inst.Mnemonic, snum)

			case "NOP":
				return fmt.Sprintf("%s\t%d\tNOP", line, *memCounter), fmt.Sprintf("%s\t%d\tNOP", line, *memCounter)
			case "N/A":
				return fmt.Sprintf("%s \t%d \tNOP", line, *memCounter), fmt.Sprintf("%s \t%d \tNOP", line, *memCounter)
			case "BREAK":
				return fmt.Sprintf("%s %s %s %s %s %s \t%d \t%s", line[:8], line[8:11], line[11:16], line[16:21], line[21:26], line[26:], *memCounter, inst.Mnemonic), fmt.Sprintf("\t%d \t%s", *memCounter, inst.Mnemonic)
			}

		}
	} else {

		return fmt.Sprintf("Unknown instruction with opcode: %s at address %d", opcode, *memCounter), fmt.Sprintf("Unknown instruction with opcode: %s at address %d", opcode, *memCounter)
	}

	// Data after break
	if len(line) == 32 {
		binaryData := line        // Assuming the data after "BREAK" is the entire line
		if binaryData[0] == '1' { // Check if the most significant bit is 1
			// Convert from two's complement to positive binary number
			invertedBinaryData := ""
			for _, bit := range binaryData {
				if bit == '0' {
					invertedBinaryData += "1"
				} else {
					invertedBinaryData += "0"
				}
			}
			positiveBinaryData := addBinary(invertedBinaryData, "1")
			decInt := -binaryToDecimal(positiveBinaryData)
			return fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt), fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt)
		} else {
			decInt := binaryToDecimal(binaryData)
			return fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt), fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt)
		}
	}

	return fmt.Sprintf("Invalid instruction at address %d", *memCounter), fmt.Sprintf("Invalid instruction at address %d", *memCounter)
}

func extractBits(line string, start, end int) int {
	// Extract a substring of bits from the line based on the provided start and end positions
	bits := line[start : end+1]
	// Convert the binary string to an integer
	value, err := strconv.ParseInt(bits, 2, 64)
	if err != nil {

		log.Fatal(err)
	}
	return int(value)
}

func binToDec(binline string) int {

	index := 31
	decimalNum := 0

	tempdecimalNum := 0
	for index != 0 {
		for index == 31 {
			templine := binline[index-1 : index]
			ttempline, _ := strconv.Atoi(templine)
			tempdecimalNum = tempdecimalNum + (ttempline * int(math.Pow(2, float64(index))))
			index--
		}
		templine := binline[index-1 : index]
		ttempline, _ := strconv.Atoi(templine)
		decimalNum = decimalNum + (ttempline * int(math.Pow(2, float64(index))))
		index--

	}
	decimalNum = decimalNum - tempdecimalNum
	return decimalNum
}

func twosComplement(binStr string, bitSize int) int {

	num, _ := strconv.ParseInt(binStr, 2, bitSize)

	num = (1 << len(binStr)) - num

	return -int(num)
}

func addBinary(a, b string) string {
	maxLength := max(len(a), len(b))
	a = padLeft(a, '0', maxLength)
	b = padLeft(b, '0', maxLength)

	carry := 0
	result := ""
	for i := maxLength - 1; i >= 0; i-- {
		bitA := int(a[i] - '0')
		bitB := int(b[i] - '0')
		sum := bitA + bitB + carry
		result = strconv.Itoa(sum%2) + result
		carry = sum / 2
	}
	if carry > 0 {
		result = "1" + result
	}
	return result
}

func binaryToDecimal(binaryStr string) int {
	result := 0
	length := len(binaryStr)
	for i, bit := range binaryStr {
		if bit == '1' {
			result += 1 << (length - 1 - i)
		}
	}
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func padLeft(str string, padChar byte, length int) string {
	for len(str) < length {
		str = string(padChar) + str
	}
	return str
}

func (s *Simulator) displayState(w io.Writer, breakI int, decodedLines []string) {

	index := (s.PC - 96) / 4

	// Get the full line from decodedLines
	fullLine := decodedLines[index]

	// Split the line by tab character
	parts := strings.Split(fullLine, "\t")

	// Check if there are enough parts after splitting
	if len(parts) > 2 {
		// The second-to-last part should be the instruction
		instruction := parts[len(parts)-2]
		// The last part should be the operands
		operands := parts[len(parts)-1]

		// Concatenate the instruction and operands
		fullInstruction := instruction + " " + operands

		fmt.Fprintf(w, "====================\n cycle:%d\t%d\t%s\n", s.Cycle, s.PC, fullInstruction)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "registers:\n")
	}

	for row := 0; row < 4; row++ {
		fmt.Fprintf(w, "r%02d:", row*8)
		for col := 0; col < 8; col++ {
			fmt.Fprintf(w, "\t%d\t", s.Registers[row*8+col])
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "\ndata:\n")

	startingAddress := 96 + breakI*4
	memoryOffset := startingAddress // Since your addresses directly map to indices

	for i := 0; i < len(s.Memory)-memoryOffset; i += 8 {
		address := startingAddress + i*4 // Address increments by 8 each loop iteration
		fmt.Fprintf(w, "%d:", address)   // Print the memory address
		for j := 0; j < 8; j++ {
			arrayIndex := memoryOffset + i + j
			if arrayIndex < len(s.Memory) {
				fmt.Fprintf(w, "\t%d", s.Memory[arrayIndex])
			} else {
				fmt.Fprintf(w, "\t0") // Pad with zeros if index is out of bounds
			}
		}
		fmt.Fprintln(w)
	}

	s.Cycle += 1

}

func (s *Simulator) executeRType(opcode string, rm int, rn int, rd int, imm int) {

	//this line is to test it works correctly given that the registers will always be 0 without I instruction support
	//s.Registers[rm] = 25
	//temporary value to test data output
	//s.Memory = append(s.Memory, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

	switch opcode {
	case "ADD":
		s.Registers[rd] = int32(s.Registers[rm] + s.Registers[rn])
	case "SUB":
		s.Registers[rd] = int32(s.Registers[rn] - s.Registers[rm])
	case "AND":
		s.Registers[rd] = int32(s.Registers[rm] & s.Registers[rn])
	case "ORR":
		s.Registers[rd] = int32(s.Registers[rm] | s.Registers[rn])
	case "EOR":
		s.Registers[rd] = int32(s.Registers[rm] ^ s.Registers[rn])
	case "LSL":
		s.Registers[rd] = int32(s.Registers[rn] << int32(imm))
	case "ASR":
		s.Registers[rd] = int32(uint32(s.Registers[rn]) >> uint32(imm))
	case "LSR":
		s.Registers[rd] = int32(uint32(s.Registers[rn]) >> uint32(imm))
	}
}

func (s *Simulator) executeDType(opcode string, address, rn int, rt int) {
	s.ensureMemoryInitialized(rn + address)
	switch opcode {
	case "LDUR":
		// Load from memory: Rt = M[Rn + address]
		s.Registers[rt] = s.Memory[int(s.Registers[rn])+address*4]
	case "STUR":

		memoryAddress := (int(s.Registers[rn]) + address*4)

		// Ensure memory is large enough
		if memoryAddress >= len(s.Memory) {
			// Resize memory slice to accommodate new address
			newMemory := make([]int32, memoryAddress+8) // +8 to pad with zeros
			copy(newMemory, s.Memory)
			s.Memory = newMemory
		}

		// Store the value in memory
		s.Memory[memoryAddress] = s.Registers[rt]
	}
}

func (s *Simulator) executeIType(opcode string, rn int, rd int, immediate int) {

	// Add immediate: Rd = Rn + immediate
	switch opcode {
	case "ADDI":
		s.Registers[rd] = s.Registers[rn] + int32(immediate)
	case "SUBI":
		s.Registers[rd] = s.Registers[rn] - int32(immediate)
	}
}

func (s *Simulator) executeCBType(opcode string, rn int, offset int) {
	switch opcode {
	case "CBZ":
		// Branch if zero
		if s.Registers[rn] == 0 {
			s.PC += int32(offset) * 4
			s.BranchT = true
		}
	case "CBNZ":
		// Branch if not zero
		if s.Registers[rn] != 0 {
			s.PC += int32(offset) * 4
			s.BranchT = true
		}
	}
}

func (s *Simulator) executeIMType(rd int, value int, shift int) {
	// Move value into Rd with shift
	s.Registers[rd] = int32(value) << uint32(shift)
}

func (s *Simulator) executeBType(offset int) {
	// Branch to offset
	s.PC += int32(offset) * 4
	s.BranchT = true
}

func defineOpcodeSim(line string, memCounter *int, s *Simulator) (string, string) {

	line = strings.ReplaceAll(line, " ", "")
	var opcode string = ""
	var exists bool
	var inst Instruction

	// Ensure the line is long enough to contain the opcode
	if len(line) >= 6 { // Minimum opcode size is 6

		if len(line) >= 32 {
			opcode = line[:32]
			inst, exists = opcodeMap[opcode]
		}

		// Check for 11-bit opcode
		if !exists && len(line) >= 11 {
			opcode = line[:11]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 10-bit opcode
		if !exists && len(line) >= 10 {
			opcode = line[:10]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 9-bit opcode
		if !exists && len(line) >= 9 {
			opcode = line[:9]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 8-bit opcode
		if !exists && len(line) >= 8 {
			opcode = line[:8]
			inst, exists = opcodeMap[opcode]
		}

		// If not found, check for 6-bit opcode
		if !exists && len(line) >= 6 {
			opcode = line[:6]
			inst, exists = opcodeMap[opcode]
		}

		// Check if the opcode exists in the opcodeMap
		if exists {
			// Determine the type of instruction and extract relevant bits
			switch inst.Type {

			case "R":
				rm := extractBits(line, 11, 15)
				rn := extractBits(line, 22, 26)
				rd := extractBits(line, 27, 31)
				imm := 0
				switch inst.Mnemonic {
				case "LSR", "LSL", "ASR":
					imm = extractBits(line, 16, 21)
					return fmt.Sprintf("%s %s %s %s %s \t%d \t%s \tR%d, R%d, #%d", line[:11], line[11:16], line[16:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rd, rn, imm), fmt.Sprintf("\t%d \t%s \tR%d, R%d, #%d", *memCounter, inst.Mnemonic, rd, rn, imm)
				default:
					return fmt.Sprintf("%s %s %s %s %s \t%d \t%s \tR%d, R%d, R%d", line[:11], line[11:16], line[16:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rd, rn, rm), fmt.Sprintf("\t%d \t%s \tR%d, R%d, R%d", *memCounter, inst.Mnemonic, rd, rn, rm)
				}

			case "CB":
				imm := extractBits(line, 8, 26)
				rt := extractBits(line, 27, 31)
				var snum int32

				binaryImm := fmt.Sprintf("%019b", imm) // Convert imm to a 19-bit binary string
				if binaryImm[0] == '1' {               // Check if the most significant bit is 1
					// Convert from two's complement to positive binary number
					invertedBinaryImm := ""
					for _, bit := range binaryImm {
						if bit == '0' {
							invertedBinaryImm += "1"
						} else {
							invertedBinaryImm += "0"
						}
					}
					positiveBinaryImm := addBinary(invertedBinaryImm, "1")
					snum = -int32(binaryToDecimal(positiveBinaryImm))
				} else {
					snum = int32(binaryToDecimal(binaryImm))
				}

				return fmt.Sprintf("%s %s %s  \t%d \t%s \tR%d, #%d", line[:8], line[8:27], line[27:], *memCounter, inst.Mnemonic, rt, snum), fmt.Sprintf("\t%d \t%s \tR%d, #%d", *memCounter, inst.Mnemonic, rt, snum)

			case "I":
				imm := extractBits(line, 10, 21)
				rn := extractBits(line, 22, 26)
				rd := extractBits(line, 27, 31)
				negBitMask := 0x800 // figure out if 12 bit num is neg
				extendMask := 0xFFFFF000
				var simm int32
				simm = int32(imm)
				if (negBitMask & imm) > 0 { // is it?
					imm = imm | extendMask // if so extend with 1's
					imm = imm ^ 0xFFFFFFFF // 2s comp
					simm = int32(imm + 1)
					simm = simm * -1 // add neg sign
				}

				return fmt.Sprintf("%s %s %s %s \t%d  \t%s \tR%d, R%d, #%d", line[:10], line[10:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rd, rn, simm), fmt.Sprintf("\t%d  \t%s \tR%d, R%d, #%d", *memCounter, inst.Mnemonic, rd, rn, simm)

			case "IM":
				immlo := extractBits(line, 9, 10)
				immhi := extractBits(line, 11, 26)
				rd := extractBits(line, 27, 31)
				shiftAmount := immlo * 16
				if inst.Mnemonic == "MOVZ" {
					return fmt.Sprintf("%s %s %s %s \t%d \t%s \tR%d, %d, LSL %d", line[:9], line[9:11], line[11:27], line[27:], *memCounter, inst.Mnemonic, rd, immhi, shiftAmount), fmt.Sprintf("\t%d \t%s \tR%d, %d, LSL %d", *memCounter, inst.Mnemonic, rd, immhi, shiftAmount)
				} else if inst.Mnemonic == "MOVK" {
					return fmt.Sprintf("%s %s %s %s \t%d \t%s \tR%d, %d, LSL %d", line[:9], line[9:11], line[11:27], line[27:], *memCounter, inst.Mnemonic, rd, immhi, shiftAmount), fmt.Sprintf("\t%d \t%s \tR%d, %d, LSL %d", *memCounter, inst.Mnemonic, rd, immhi, shiftAmount)
				}

			case "D":
				imm := extractBits(line, 11, 19)
				rn := extractBits(line, 22, 26)
				rt := extractBits(line, 27, 31)
				return fmt.Sprintf("%s %s %s %s %s \t%d \t%s \tR%d, [R%d, #%d]", line[:11], line[11:20], line[20:22], line[22:27], line[27:], *memCounter, inst.Mnemonic, rt, rn, imm), fmt.Sprintf("\t%d \t%s \tR%d, [R%d, #%d]", *memCounter, inst.Mnemonic, rt, rn, imm)

			case "B":
				opcodePart := line[:6]
				rawOffset := extractBits(line, 7, 31)
				var snum int32

				binaryOffset := fmt.Sprintf("%025b", rawOffset) // Convert rawOffset to a 25-bit binary string
				if binaryOffset[0] == '1' {                     // Check if the most significant bit is 1
					// Convert from two's complement to positive binary number
					invertedBinaryOffset := ""
					for _, bit := range binaryOffset {
						if bit == '0' {
							invertedBinaryOffset += "1"
						} else {
							invertedBinaryOffset += "0"
						}
					}
					positiveBinaryOffset := addBinary(invertedBinaryOffset, "1")
					snum = -int32(binaryToDecimal(positiveBinaryOffset))
				} else {
					snum = int32(binaryToDecimal(binaryOffset))
				}

				return fmt.Sprintf("%s %s   \t%d \t%s   \t#%d", opcodePart, line[6:], *memCounter, inst.Mnemonic, snum), fmt.Sprintf("\t%d \t%s   \t#%d", *memCounter, inst.Mnemonic, snum)

			case "NOP":
				return fmt.Sprintf("%s\t%d\tNOP", line, *memCounter), fmt.Sprintf("%s\t%d\tNOP", line, *memCounter)
			case "N/A":
				return fmt.Sprintf("%s \t%d \tNOP", line, *memCounter), fmt.Sprintf("%s \t%d \tNOP", line, *memCounter)
			case "BREAK":
				return fmt.Sprintf("%s %s %s %s %s %s \t%d \t%s", line[:8], line[8:11], line[11:16], line[16:21], line[21:26], line[26:], *memCounter, inst.Mnemonic), fmt.Sprintf("\t%d \t%s", *memCounter, inst.Mnemonic)
			}

		}
	} else {

		return fmt.Sprintf("Unknown instruction with opcode: %s at address %d", opcode, *memCounter), fmt.Sprintf("Unknown instruction with opcode: %s at address %d", opcode, *memCounter)
	}

	// Data after break
	if len(line) == 32 {
		binaryData := line        // Assuming the data after "BREAK" is the entire line
		if binaryData[0] == '1' { // Check if the most significant bit is 1
			// Convert from two's complement to positive binary number
			invertedBinaryData := ""
			for _, bit := range binaryData {
				if bit == '0' {
					invertedBinaryData += "1"
				} else {
					invertedBinaryData += "0"
				}
			}
			positiveBinaryData := addBinary(invertedBinaryData, "1")
			decInt := -binaryToDecimal(positiveBinaryData)
			return fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt), fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt)
		} else {
			decInt := binaryToDecimal(binaryData)
			return fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt), fmt.Sprintf("%s \t%d \t%d", line, *memCounter, decInt)
		}
	}

	return fmt.Sprintf("Invalid instruction at address %d", *memCounter), fmt.Sprintf("Invalid instruction at address %d", *memCounter)
}

func (s *Simulator) ensureMemoryInitialized(upToIndex int) {
	// Check if the memory slice is shorter than the required length
	if len(s.Memory) < upToIndex+1 {
		// Calculate the number of elements to append
		elementsToAdd := upToIndex + 1 - len(s.Memory)

		// Create a slice of zeros to append
		zeros := make([]int32, elementsToAdd)

		// Append the zeros to the memory slice
		s.Memory = append(s.Memory, zeros...)
	}
}

func (s *Simulator) displayStateUsingPC(w io.Writer, breakI int, decodedLines []string, PC int32) {

	index := (PC - 96) / 4

	// Get the full line from decodedLines
	fullLine := decodedLines[index]

	// Split the line by tab character
	parts := strings.Split(fullLine, "\t")

	// Check if the current instruction is BREAK
	if strings.Contains(fullLine, "BREAK") {
		// Format the output for BREAK instruction
		fmt.Fprintf(w, "====================\n cycle:%d\t%d\tBREAK\n", s.Cycle, PC)
	} else if len(parts) > 2 {
		// The second-to-last part should be the instruction
		instruction := parts[len(parts)-2]
		// The last part should be the operands
		operands := parts[len(parts)-1]

		// Concatenate the instruction and operands
		fullInstruction := instruction + "\t" + operands

		fmt.Fprintf(w, "====================\n cycle:%d\t%d\t%s\n", s.Cycle, PC, fullInstruction)
	} else {
		// Handle unexpected format
		fmt.Fprintf(w, "Error: Unexpected instruction format at PC %d\n", PC)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "registers:\n")

	for row := 0; row < 4; row++ {
		fmt.Fprintf(w, "r%02d:", row*8)
		for col := 0; col < 8; col++ {
			fmt.Fprintf(w, "\t%d\t", s.Registers[row*8+col])
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "\ndata:\n")

	startingAddress := 96 + breakI*4
	memoryOffset := startingAddress // Since your addresses directly map to indices

	for i := 0; i < len(s.Memory)-memoryOffset; i += 8 {
		address := startingAddress + i*4 // Address increments by 8 each loop iteration
		fmt.Fprintf(w, "%d:", address)   // Print the memory address
		for j := 0; j < 8; j++ {
			arrayIndex := memoryOffset + i + j
			if arrayIndex < len(s.Memory) {
				fmt.Fprintf(w, "\t%d", s.Memory[arrayIndex])
			} else {
				fmt.Fprintf(w, "\t0") // Pad with zeros if index is out of bounds
			}
		}
		fmt.Fprintln(w)
	}

	s.Cycle += 1

}
