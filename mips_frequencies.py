#!/usr/bin/pypy

import sys, struct, collections, mips

# mips_frequencies.py - Sort traces by frequency of execution and
#   provide guesses as to where they are in a file
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

def extract_procedures(code_file):
    result = {}
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
                result[procedure_pc] = procedure
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
    return result

def build_map(op_lists):
    result = {}
    for op_list in op_lists.itervalues():
        for op in op_list:
            result[op.pc] = op
    return result

def guess_procedures(mem_trace, procedures):
    result = {}
    for pc, procedure in procedures.iteritems():
        # Shortcut: If the trace is longer than the procedure, the trace
        # cannot be in the procedure.
        if len(mem_trace) > len(procedure):
            continue
        for i in xrange(len(procedure) - len(mem_trace) + 1):
            found = True
            for j in xrange(len(mem_trace)):
                if procedure[i + j].opcode != mem_trace[j].opcode:
                    found = False
                    break
            if found:
                result[pc] = procedure
                break
    return result

def find_procedures(trace_pc, file_procedures, mem_traces, mem_map):
    mem_trace = mem_traces[mem_pc][:]
    guesses = guess_procedures(mem_trace, file_procedures)
    # Try extending the trace with other adjacent traces preceding it in
    # memory.
    while len(guesses) > 1:
        prev_start = trace_pc
        if mem_trace[0].opcode & 0xFFFF8003 == 0x27BD8000:
            # On the left side, we have encountered a stack adjustment.
            # This is probably the start of a procedure. Stop here.
            break
        while True:
            if not trace_pc - 4 in mem_map:
                break
            trace_pc -= 4
            mem_trace.insert(0, mem_map[trace_pc])
            if trace_pc in mem_traces:
                # Here, we've reached the start of another trace boundary.
                break
        if trace_pc == prev_start:
            # We couldn't even expand the trace. Give up; go to the right.
            break
        guesses = guess_procedures(mem_trace, guesses)
    # Try extending the trace with other adjacent traces following it in
    # memory.
    while len(guesses) > 1:
        prev_len = len(mem_trace)
        if len(mem_trace) >= 2 and isinstance(mem_trace[-2], mips.JR) and mem_trace[-2].s == 31:
            # On the right side, we have encountered the end of a procedure.
            # Stop here.
            break
        while True:
            if not trace_pc + 4 * len(mem_trace) in mem_map:
                break
            mem_trace.append(mem_map[trace_pc + 4 * len(mem_trace)])
            if trace_pc + 4 * len(mem_trace) in mem_traces:
                # Here, the next instruction would start a new trace.
                break
        if len(mem_trace) == prev_len:
            # We couldn't even expand the trace. Give up and give results.
            break
        guesses = guess_procedures(mem_trace, guesses)
    return guesses

if __name__ == '__main__':
    # Grab the procedures of the file, keyed by their starting file offsets.
    with open(sys.argv[1], 'rb') as code_file:
        file_procedures = extract_procedures(code_file)

    mem_traces = {}
    mem_trace_counts = collections.Counter()
    in_exec_counts = False
    for line in sys.stdin:
        if line.startswith('BLOCK '):
            colon_tokens = [token.strip() for token in line[6:].split(':')]
            pc = int(colon_tokens[0], 16)
            mips_opcodes = [int(op_str, 16) for op_str in colon_tokens[1].split(' ')]
            mips_ops = [mips.disassemble(pc + n * 4, mips_opcode) for n, mips_opcode in enumerate(mips_opcodes)]
            mem_traces[pc] = mips_ops
        elif line.startswith('TRACEEXEC'):
            in_exec_counts = True
        elif line.startswith('ENDTRACEEXEC'):
            break
        elif in_exec_counts:
            colon_tokens = [token.strip() for token in line.split(':')]
            pc = int(colon_tokens[0], 16)
            count = int(colon_tokens[1])
            mem_trace_counts[pc] = count
    del in_exec_counts
    mem_map = build_map(mem_traces)

    # Now we get to show the most frequent traces. Ready? Go!
    print "Most frequently-executed traces:"
    for n, (mem_pc, count) in enumerate(mem_trace_counts.most_common()):
        print "-- #%d (%d executions) --" % (n + 1, count)
        print "At %08X on the Nintendo 64" % (mem_pc)

        trace_ops = mem_traces[mem_pc]
        for op in trace_ops:
            print op
        print

        # Get guesses as to where the procedure containing this trace is
        # in the file.
        result = find_procedures(mem_pc, file_procedures, mem_traces, mem_map)
        if len(result) == 0:
            print "Not found in any procedure in the file"
            print
        elif len(result) == 1:
            for file_offset, procedure in result.iteritems():
                print "Found in a procedure at offset %08X within the file" % (file_offset)
                # for op in procedure:
                #     print op
                print
        elif len(result) <= 8:
            print "Found in procedures at these offsets within the file:"
            print
            for file_offset, procedure in result.iteritems():
                print "- offset %08X" % (file_offset)
                # for op in procedure:
                #     print op
                print
        else:
            print "Found in %d procedures (too generic)" % (len(result))
            print
