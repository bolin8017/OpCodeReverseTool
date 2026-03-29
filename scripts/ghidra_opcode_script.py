"""Ghidra postScript for opcode extraction.

Runs inside Ghidra's headless analyzer environment.
Receives one argument: the path where the temp CSV should be written.

Uses .format() instead of f-strings for Jython/Ghidrathon compatibility.
"""
import os
import csv
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand

argv = getScriptArgs()

if len(argv) < 1:
    raise ValueError("Missing argument: CSV output path")

csv_output_path = argv[0]
file_name = currentProgram().getName()

memory_blocks = currentProgram().getMemory().getBlocks()

if not memory_blocks:
    raise Exception("{}: No memory blocks found - file may be packed, damaged, or incomplete".format(file_name))

all_opcodes = []
for block in memory_blocks:
    section_name = block.getName()
    address_set = AddressSet(block.getStart(), block.getEnd())

    # Manually disassemble since we use -noanalysis
    disassemble_cmd = DisassembleCommand(address_set, address_set, True)
    disassemble_cmd.applyTo(currentProgram())

    instructions = currentProgram().getListing().getInstructions(address_set, True)
    for instr in instructions:
        addr = int(instr.getAddress().getOffset())
        opcode = str(instr).split(' ')[0]
        all_opcodes.append([addr, opcode, section_name])

if not all_opcodes:
    raise Exception("{}: No instructions found in any memory block".format(file_name))

# Create output directory if needed
output_dir = os.path.dirname(csv_output_path)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['addr', 'opcode', 'section_name'])
    csvwriter.writerows(all_opcodes)
