#!/usr/bin/python

from __future__ import division

# mips_simplify.py - Front-end to mips.disassemble() and simplify()
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

import sys, mips

def simplify_notice(string):
    print "Simplification in %s" % (string)

mips.simplify_notice = simplify_notice

if __name__ == '__main__':
    for line in sys.stdin:
        if line.startswith('BLOCK '):
            print "-- Trace --"

            colon_tokens = [token.strip() for token in line[6:].split(':')]
            pc = int(colon_tokens[0], 16)
            mips_opcodes = [int(op_str, 16) for op_str in colon_tokens[1].split(' ')]
            mips_ops = [mips.disassemble(pc + n * 4, mips_opcode) for n, mips_opcode in enumerate(mips_opcodes)]

            int_state = mips.IntState()
            for n in xrange(len(mips_ops)):
                mips_op = mips_ops[n].simplify()
                print mips_op.as_string()
                mips_ops[n] = simplified_op = mips_op.update_int_state(int_state)
                if simplified_op is not mips_op:
                    print "%s= %s" % (" " * 8, simplified_op.as_string(pc=False))
