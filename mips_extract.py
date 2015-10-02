#!/usr/bin/python

# mips_extract.py - Extract MIPS procedures from files
# Copyright (C) 2015 Nebuleon Fumika <nebuleon.fumika@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import sys, struct, mips

mips.joffset = lambda pc, n: "%+d    ; to %08X" % (n, pc + 4 + (n << 2))
mips.jabs = lambda pc, n: "?%07X    ; in 256 MiB segment at run-time" % (n << 2)

def get_block_boundaries(procedure):
    """Separates the given procedure into blocks. A block is made at a
    location when it is the target of a branch from inside the procedure, or
    when it is after a branch (and its delay slot).

    The return value is a list containing as many bool values as there are
    instructions in the procedure. An element is True if it is a block
    boundary."""
    result = [False] * len(procedure)
    for i in xrange(len(procedure)):
        if isinstance(procedure[i], mips.DSBranch) and i + 2 < len(procedure):
            result[i + 2] = True
        try:
            target = i + 1 + procedure[i].joffset
            if 0 <= target < len(procedure):
                result[target] = True
        except AttributeError:
            pass
    return result

def optimize(procedure, is_boundary):
    result = [None] * len(procedure)
    int_state = mips.IntState()
    for n, op in enumerate(procedure):
        if is_boundary[n]:
            int_state = mips.IntState()
        result[n] = op.simplify().update_int_state(int_state)
    return result

if __name__ == '__main__':
    procedure, procedure_pc, in_procedure = [], 0, 0
    with open(sys.argv[1], 'rb') as code_file:
        procedure_pc, procedure, in_procedure = 0, [], 0
        while True:
            opcode_str = code_file.read(4)
            if len(opcode_str) != 4:
                break
            # >L is for big-endian files. Use <L for little-endian files.
            opcode = struct.unpack('>L', opcode_str)[0]
            if in_procedure:
                pc = code_file.tell() - 4
                op = mips.disassemble(pc, opcode)
                if isinstance(op, mips.JR) and op.s == 31:
                    # JR $31 = return from procedure. We're about to finish!
                    # We just need to get the delay slot, so 1 instruction is
                    # left.
                    procedure.append(op)
                    in_procedure = 1
                elif len(procedure) > 16384 or isinstance(op, mips.Unknown):
                    # We are probably parsing data that happened to look like
                    # a procedure. Just ignore it.
                    procedure, in_procedure = [], 0
                elif in_procedure == 1:
                    # We've got the delay slot of the JR $31. We're finished!
                    procedure.append(op)
                    is_boundary = get_block_boundaries(procedure)
                    procedure = optimize(procedure, is_boundary)
                    print '.proc %08X' % (procedure_pc)
                    print
                    for n, op in enumerate(procedure):
                        if is_boundary[n]:
                            print "; %08X:" % (op.pc)
                        if op.opcode != 0 and isinstance(op, mips.SLL) and op.d == 0:
                            print "%-25s%s %s" % ("DEL", "; automatically-suggested deletion of", mips.disassemble(op.pc, op.opcode).as_string(pc=False, opcode=False))
                        else:
                            print op.as_string(pc=False, opcode=False)
                    print
                    print '.end'
                    print
                    procedure, in_procedure = [], 0
                else:
                    procedure.append(op)
            else:
                # This checks for 'ADDIU $29, $29, <negative 4-byte-aligned>'.
                # That's a stack adjustment. Until now we haven't parsed
                # opcodes because we were probably in data, but we now need to
                # parse them, as a procedure is starting!
                if opcode & 0xFFFF8003 == 0x27BD8000:
                    procedure_pc = pc = code_file.tell() - 4
                    op = mips.disassemble(pc, opcode)
                    procedure, in_procedure = [op], 2
