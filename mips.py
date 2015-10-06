# mips.py - Module to provide disassembly and simplification of MIPS opcodes
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

from __future__ import division

def as_unsigned_16(n):
    """Converts the possibly negative number 'n' to its (positive) two's
    complement representation in 16 bits."""
    if n >= 0:
        return n & 0xFFFF
    else:
        return (0x10000 + n) & 0xFFFF

def as_signed_16(n):
    """Converts the two's complement representation of 'n' to its possibly
    negative representation in 16 bits."""
    n = n & 0xFFFF
    if n < 0x8000:
        return n
    else:
        return -0x10000 + n

def as_unsigned_32(n):
    """Converts the possibly negative number 'n' to its (positive) two's
    complement representation in 32 bits."""
    if n >= 0:
        return n & 0xFFFFFFFF
    else:
        return (0x100000000 + n) & 0xFFFFFFFF

def as_signed_32(n):
    """Converts the two's complement representation of 'n' to its possibly
    negative representation in 32 bits."""
    n = n & 0xFFFFFFFF
    if n < 0x80000000:
        return n
    else:
        return -0x100000000 + n

def as_unsigned_64(n):
    """Converts the possibly negative number 'n' to its (positive) two's
    complement representation in 64 bits."""
    if n >= 0:
        return n & 0xFFFFFFFFFFFFFFFF
    else:
        return (0x10000000000000000 + n) & 0xFFFFFFFFFFFFFFFF

def as_signed_64(n):
    """Converts the two's complement representation of 'n' to its possibly
    negative representation in 64 bits."""
    n = n & 0xFFFFFFFFFFFFFFFF
    if n < 0x8000000000000000:
        return n
    else:
        return -0x10000000000000000 + n

def sign_extend_64(n, nbits):
    """Sign-extend 'n', an 'nbits'-bit-wide value, to 64 bits."""
    n &= (1 << nbits) - 1
    if n & (1 << (nbits - 1)):
        return n | (0x10000000000000000 - (1 << nbits))
    else:
        return n

c0regs = ["Index", "Random", "EntryLo0", "EntryLo1", "Context", "PageMask", "Wired", "$7", "BadVAddr", "Count", "EntryHi", "Compare", "Status", "Cause", "EPC", "PrevID", "Config", "LLAddr", "WatchLo", "WatchHi", "XContext", "$21", "$22", "$23", "$24", "$25", "$26", "$27", "TagLo", "TagHi", "ErrorEPC", "$31"]

# - - - OUTPUT FORMATTING FUNCTIONS - - -
# You can replace these functions if you want this module to output things
# differently. For example, mips.ri = code_object.

def ri(n):
    """Returns a representation of an integer register."""
    return "$%d" % (n)

def excode(n):
    """Returns a representation of a 20-bit exception code (BREAK, SYSCALL)."""
    return "0x%05X" % (n)

def joffset(pc, n):
    """Returns a representation of a relative jump offset."""
    return "%08X" % (pc + 4 + (n << 2))

def jabs(pc, n):
    """Returns a representation of a segment-relative absolute jump."""
    return "%08X" % (((pc + 4) & 0xF0000000) | (n << 2))

def rc0(n):
    """Returns a representation of a Coprocessor 0 register."""
    return c0regs[n]

def rc1(n):
    """Returns a representation of a Coprocessor 1 (FPU) register."""
    return "$f%d" % (n)

def rc1c(n):
    """Returns a representation of a Coprocessor 1 (FPU) control register."""
    return "FCR%d" % (n)

def imm16s(n):
    """Returns a representation of a signed immediate."""
    return "%d" % (n)

def imm16u(n):
    """Returns a representation of an unsigned immediate, meant for bitwise
    immediate instructions and LUI."""
    return "0x%04X" % (n)

def memri16(addr_reg, n):
    """Returns a representation of a memory reference."""
    return "%d(%s)" % (n, ri(addr_reg))

def cache(n):
    """Returns a representation of a 6-bit CACHE operation number."""
    return "0x%02X" % (n)

# - - - OUTPUT FUNCTIONS - - -
# You can replace these functions if you want this module to output things
# differently. For example, mips.ri = code_object.

def simplify_notice(string):
    """Can be reassigned to a function that prints simplification information."""
    pass

# - - - OPCODE CLASSES - - -

class Op(object):
    def __init__(self, pc, opcode):
        if pc < 0 or pc > 0xFFFFFFFF or pc & 3 != 0:
            raise ValueError("invalid program counter: %d" % (pc))
        if opcode < 0 or opcode > 0xFFFFFFFF:
            raise ValueError("invalid MIPS opcode: %d" % (opcode))
        self.pc, self.opcode = pc, opcode
        self.attribs = set()
        self.add_attributes()
    def simplify(self):
        """Attempts to simplify this opcode, using a single more common opcode
        to implement common operations such as loading 0 into a register,
        copying a value into another register (64-bit), sign-extending a value
        into another register (32-bit), loading small constants, and NOP.

        If the opcode has been simplified, a new, distinct object is returned,
        with the original opcode kept around for diagnostic purposes.

        If the opcode has not been simplified, 'self' is returned."""
        return self  # By default, there are no possible simplifications
    def get_int_reads(self):
        """Gives the MIPS integer registers read by this opcode.

        The return value is a bitmask having bit 'i' set if integer register
        'i' is read, or unset otherwise. Bit 0 is the least-significant bit,
        and bit 31 is the most-significant bit.

        The default implementation returns all bits set: unless told
        otherwise, no optimisations will be attempted across this opcode on
        the basis of register reads or the lack thereof, which is a safe
        default."""
        return 0xFFFFFFFF
    def get_int_writes(self):
        """Gives the MIPS integer registers written by this opcode.

        The return value is a bitmask having bit 'i' set if integer register
        'i' is written, or unset otherwise. Bit 0 is the least-significant
        bit, and bit 31 is the most-significant bit.

        The default implementation returns all bits set: unless told
        otherwise, no optimisations will be attempted across this opcode on
        the basis of register writes or the lack thereof, which is a safe
        default."""
        return 0xFFFFFFFF
    def add_attributes(self):
        """Adds this opcode's individual attributes to its attribs set.
        Those attributes apply even without any context, including knowing the
        preceding or following instructions.

        For more information on attributes, see get_attributes()."""
        pass
    def add_pair_attributes(self, succ):
        """Add attributes to this opcode's attribs set, knowing that the
        successor opcode is 'succ'. If this opcode is a branch with a delay
        slot, 'succ' is actually executed between the reads done by this
        opcode and the update of the Program Counter after the delay slot.

        For more information on attributes, see get_attributes()."""
        pass
    def get_attributes(self):
        """Returns a set of the various attributes of this opcode, which
        enable optimisations.

        The possible attributes are:
        'noop' - if this opcode is NOP.
        'noexcept' - if this opcode cannot raise the TLB Refill or Trap
        exceptions.
        (The check to create the Coprocessor Unusable exception is done at
        the start of a trace if any instruction in the trace is an FPU
        instruction. FPU instructions use the Cop1 mixin.)
        'nodelay' - if this opcode is a branch and its delay slot is NOP.
        'nodelayexcept' - if this opcode is a branch and its delay slot cannot
        raise the TLB Refill or Trap exceptions.
        'reorder' - if this opcode is a branch and its delay slot does not
        write new values to the registers it reads. Otherwise, the current
        values of the registers the branch reads have to be preserved before
        the delay slot executes."""
        return self.attribs
    def copy_attributes(self, other):
        """Copies attributes from other.attribs into self.attribs.

        Returns self to allow for call chaining."""
        self.attribs = self.attribs.union(other.attribs)
        return self
    def update_int_state(self, int_state):
        """Updates the variables maintained by the IntState object given
        as the 'state' parameter.

        The default implementation marks all integer registers written by this
        opcodes as fully unknown, as well as HI and LO, and increments their
        versions. This is a safe default until told otherwise by a more
        specific implementation.

        If the opcode can be simplified due to the initial values in the state
        object, a new, distinct object is returned, with the original opcode
        kept around for diagnostic purposes, as well as the attributes copied
        from 'self'.

        If the opcode has not been simplified, 'self' is returned.
        """
        int_writes = self.get_int_writes()
        for i in xrange(1, 32):
            if int_writes & (1 << i):
                int_state.reg[i].make_unknown()
                int_state.reg[i].inc_version()
        int_state.reg_hi.make_unknown()
        int_state.reg_hi.inc_version()
        int_state.reg_lo.make_unknown()
        int_state.reg_lo.inc_version()
        return self
    def __str__(self):
        result = "%08X: <%08X>  %s" % (self.pc, self.opcode, self._str_bits())
        if len(self.attribs):
            result = "%-50s ; %s" % (result, ', '.join(self.attribs))
        return result
    def as_string(self, pc=True, opcode=False, mnemonic=True, operands=True):
        result = ''
        if pc: result += "%08X:" % (self.pc)
        if opcode:
            if len(result): result += " "
            result += "<%08X>" % (self.opcode)
        if mnemonic or operands:
            if len(result): result += " "
            if mnemonic and operands:
                result += self._str_bits()
            elif mnemonic:
                result += self._str_bits()[:9].strip()
            elif operands:
                result += self._str_bits()[10:]
        return result
    def __repr__(self):
        result, repr_bits = '0x%08X, 0x%08X' % (self.pc, self.opcode), self._repr_bits()
        if repr_bits: return '%s(%s, %s)' % (self.__class__.__name__, result, repr_bits)
        else: return '%s(%s)' % (self.__class__.__name__, result)

class RegInt0(object):
    def get_known_bits(self, mask=0xFFFFFFFFFFFFFFFF):
        return 0
    def get_known_mask(self):
        return 0xFFFFFFFFFFFFFFFF
    def get_vresion(self):
        return 0
    def is_known(self):
        return True
    def is_known_mask(self, mask):
        return True
    def set_known_bits(self, bits):
        pass
    def set_known_mask(self, mask):
        pass
    def inc_version(self):
        pass
    def add_known_bits(self, bits, mask):
        pass
    def make_known(self, bits):
        pass
    def make_unknown(self):
        pass

class RegInt(object):
    def __init__(self, n):
        self.n, self.known_bits, self.known_mask, self.version = n, 0, 0, 0
    def get_known_bits(self, mask=0xFFFFFFFFFFFFFFFF):
        return self.known_bits & self.known_mask & mask
    def get_known_mask(self):
        return self.known_mask & 0xFFFFFFFFFFFFFFFF
    def get_version(self):
        return self.version
    def is_known(self):
        return self.known_mask == 0xFFFFFFFFFFFFFFFF
    def is_known_mask(self, mask):
        return self.known_mask & mask == mask
    def set_known_bits(self, bits):
        self.known_bits = bits & 0xFFFFFFFFFFFFFFFF
    def set_known_mask(self, mask):
        self.known_mask = mask & 0xFFFFFFFFFFFFFFFF
    def inc_version(self):
        self.version += 1
        return self.version
    def add_known_bits(self, bits, mask):
        self.set_known_bits((self.known_bits & self.known_mask & ~mask) | (bits & mask))
        self.set_known_mask(self.known_mask | mask)
    def make_known(self, bits):
        self.known_bits, self.known_mask = bits & 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
    def make_unknown(self):
        self.known_bits, self.known_mask = 0, 0
    def __str__(self):
        return "known %016X, mask %016X" % (self.known_bits, self.known_mask)

class IntState(object):
    def __init__(self):
        self.reg = [RegInt0()] + [RegInt(n) for n in xrange(1, 32)]
        self.reg_hi, self.reg_lo = RegInt(32), RegInt(33)

# - - - MIXINS - - -

# Integer state
class NoIntReads(object):
    def get_int_reads(self): return 0

class NoIntWrites(object):
    def get_int_writes(self): return 0

class NoIntState(object):
    def update_int_state(self, int_state):
        return self

class NoInt(NoIntReads, NoIntWrites, NoIntState, object):
    pass

# Floating-point
class Cop1(object):
    pass

# Branches
class DSBranch(NoIntWrites, NoIntState, object):
    def add_pair_attributes(self, succ):
        if not isinstance(self, DSBranchLikely) and succ.get_int_writes() & self.get_int_reads() == 0:
            self.attribs.add('reorder')
        if 'noop' in succ.attribs:
            self.attribs.add('nodelay')
        if 'noexcept' in succ.attribs:
            self.attribs.add('nodelayexcept')

class DSBranchLikely(object):
    pass

class DSBranchLink31(DSBranch):
    def get_int_writes(self): return 0x80000000
    def update_int_state(self, int_state):
        rd = int_state.reg[31]
        rd.make_known(sign_extend_64(self.pc + 8, 32))
        rd.inc_version()
        return self

# Loads and stores
class MemoryAccess(object):
    pass

class Load(MemoryAccess):
    pass

class LoadIntOffset(Load):
    def get_int_reads(self): return 1 << self.addr_reg
    def get_int_writes(self): return 1 << self.d

class LoadCop1Offset(NoIntWrites, NoIntState, Load, Cop1):
    def get_int_reads(self): return 1 << self.addr_reg

class Store(MemoryAccess):
    pass

class StoreIntOffset(NoIntWrites, NoIntState, Store):
    def get_int_reads(self): return (1 << self.addr_reg) | (1 << self.s)

class StoreCop1Offset(NoIntWrites, NoIntState, Store, Cop1):
    def get_int_reads(self): return 1 << self.addr_reg

# Attributes
class NoExcept(object):
    def add_attributes(self):
        self.attribs.add('noexcept')

# - - - PSEUDO-OPCODES - - -
def NOP(pc, opcode):
    return SLL(pc, opcode, 0, 0, 0)

def B(pc, opcode, joffset):
    return BGEZ(pc, opcode, 0, joffset)

def BAL(pc, opcode, joffset):
    return BGEZAL(pc, opcode, 0, joffset)

# - - - REAL OPCODES - - -
class SLL(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        # A shift from $0 simply loads the value 0 into a register.
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        # A shift by 0 simply copies a value from one register into another.
        # However, this instruction is 32-bit, so it doesn't simply move the
        # value; it also sign-extends it to 64 bits. The code may want to do
        # this without carrying out another operation.
        if self.a == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        known_bits = rt.get_known_bits() << self.a
        known_mask = rt.get_known_mask() << self.a
        # The lower 'a' bits are now also known to be unset.
        known_mask |= (1 << self.a) - 1
        if self.t != 0 and known_mask & 0xFFFFFFFF == 0xFFFFFFFF and known_bits & 0xFFFFFFFF == 0:
            simplify_notice("SLL: Shifting %d unset bits when $%d's lower %d bits are already unset yields 0" % (self.a, self.t, 32 - self.a))
            new_op = OR(self.pc, self.opcode, self.d, 0, 0).copy_attributes(self)
        rd.set_known_bits(sign_extend_64(known_bits, 32))
        rd.set_known_mask(sign_extend_64(known_mask, 32))
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "SLL       %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class SRL(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.a == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        known_bits = (rt.get_known_bits(0xFFFFFFFF)) >> self.a
        known_mask = (rt.get_known_mask() & 0xFFFFFFFF) >> self.a
        # The upper 'a' bits (of the lower 32) are now also known to be
        # unset.
        known_mask |= 0x100000000 - (1 << (32 - self.a))
        if known_mask & 0xFFFFFFFF == 0xFFFFFFFF and known_bits & 0xFFFFFFFF == 0:
            simplify_notice("SRL: Shifting %d unset bits when $%d's lower %d bits are already unset yields 0" % (self.a, self.t, 32 - self.a))
            new_op = OR(self.pc, self.opcode, self.d, 0, 0).copy_attributes(self)
        rd.set_known_bits(sign_extend_64(known_bits, 32))
        rd.set_known_mask(sign_extend_64(known_mask, 32))
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "SRL       %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class SRA(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.a == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = (rt.get_known_bits(0xFFFFFFFF)) >> self.a
        known_mask = (rt.get_known_mask() & 0xFFFFFFFF) >> self.a
        # If bit 31 (which is now at bit 31 - a) was known, then all copies of
        # it are known, all the way to bit 63. Otherwise, we don't know those
        # bits anymore.
        if known_mask & (1 << (31 - self.a)):
            known_bits = sign_extend_64(known_bits, 32 - self.a)
            known_mask = sign_extend_64(known_mask, 32 - self.a)
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "SRA       %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class SLLV(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.s = d, t, s
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rd = int_state.reg[self.s], int_state.reg[self.d]
        if rs.is_known_mask(0x1F):
            rt, sa = int_state.reg[self.t], rs.get_known_bits(0x1F)
            known_bits = rt.get_known_bits() << sa
            known_mask = rt.get_known_mask() << sa
            # The lower 'a' bits are now also known to be unset.
            known_mask |= (1 << sa) - 1
            rd.set_known_bits(sign_extend_64(known_bits, 32))
            rd.set_known_mask(sign_extend_64(known_mask, 32))
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "SLLV      %s, %s, %s" % (ri(self.d), ri(self.t), ri(self.s))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.s)

class SRLV(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.s = d, t, s
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rd = int_state.reg[self.s], int_state.reg[self.d]
        if rs.is_known_mask(0x1F):
            rt, sa = int_state.reg[self.t], rs.get_known_bits(0x1F)
            known_bits = (rt.get_known_bits(0xFFFFFFFF)) >> sa
            known_mask = (rt.get_known_mask() & 0xFFFFFFFF) >> sa
            # The upper 'a' bits (of the lower 32) are now also known to be
            # unset.
            known_mask |= 0x100000000 - (1 << (32 - sa))
            rd.set_known_bits(sign_extend_64(known_bits, 32))
            rd.set_known_mask(sign_extend_64(known_mask, 32))
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "SRLV      %s, %s, %s" % (ri(self.d), ri(self.t), ri(self.s))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.s)

class SRAV(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.s = d, t, s
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rd = int_state.reg[self.s], int_state.reg[self.d]
        if rs.is_known_mask(0x1F):
            rt, sa = int_state.reg[self.t], rs.get_known_bits(0x1F)
            known_bits = (rt.get_known_bits(0xFFFFFFFF)) >> sa
            known_mask = (rt.get_known_mask() & 0xFFFFFFFF) >> sa
            # If bit 31 (which is now at bit 31 - a) was known, then all copies of
            # it are known, all the way to bit 63. Otherwise, we don't know those
            # bits anymore.
            if known_mask & (1 << (31 - sa)):
                known_bits = sign_extend_64(known_bits, 32 - sa)
                known_mask = sign_extend_64(known_mask, 32 - sa)
            rd.set_known_bits(known_bits)
            rd.set_known_mask(known_mask)
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "SRAV      %s, %s, %s" % (ri(self.d), ri(self.t), ri(self.s))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.s)

class JR(DSBranch, Op):
    def __init__(self, pc, opcode, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.s = s
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "JR        %s" % (ri(self.s))
    def _repr_bits(self):
        return '%d' % (self.s)

class JALR(DSBranch, Op):
    def __init__(self, pc, opcode, s, d):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.d = s, d
    def simplify(self):
        if self.d == 0: return JR(self.pc, self.opcode, self.s)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_known(sign_extend_64(self.pc + 8, 32))
        rd.inc_version()
        return self
    def _str_bits(self):
        if self.d == 31: return "JALR      %s" % (ri(self.s))
        else:            return "JALR      %s" % (ri(self.s), ri(self.d))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.d)

class SYSCALL(NoInt, Op):
    def __init__(self, pc, opcode, code):
        super(self.__class__, self).__init__(pc, opcode)
        self.code = code
    def _str_bits(self):
        return "SYSCALL   %s" % (excode(self.code))
    def _repr_bits(self):
        return '0x%05X' % (self.code)

class BREAK(NoInt, Op):
    def __init__(self, pc, opcode, code):
        super(self.__class__, self).__init__(pc, opcode)
        self.code = code
    def _str_bits(self):
        return "BREAK     %s" % (excode(self.code))
    def _repr_bits(self):
        return '0x%05X' % (self.code)

class SYNC(NoInt, NoExcept, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "SYNC"
    def _repr_bits(self):
        return ''

class MFHI(NoExcept, NoIntReads, Op):
    def __init__(self, pc, opcode, d):
        super(self.__class__, self).__init__(pc, opcode)
        self.d = d
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        hi, rd = int_state.reg_hi, int_state.reg[self.d]
        rd.set_known_bits(hi.get_known_bits())
        rd.set_known_mask(hi.get_known_mask())
        rd.inc_version()
        return self
    def _str_bits(self):
        return "MFHI      %s" % (ri(self.d))
    def _repr_bits(self):
        return '%d' % (self.d)

class MTHI(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.s = s
    def get_int_reads(self): return 1 << self.s
    def update_int_state(self, int_state):
        rs, hi = int_state.reg[self.s], int_state.reg_hi
        hi.set_known_bits(rs.get_known_bits())
        hi.set_known_mask(rs.get_known_mask())
        hi.inc_version()
        return self
    def _str_bits(self):
        return "MTHI      %s" % (ri(self.s))
    def _repr_bits(self):
        return '%d' % (self.s)

class MFLO(NoExcept, NoIntReads, Op):
    def __init__(self, pc, opcode, d):
        super(self.__class__, self).__init__(pc, opcode)
        self.d = d
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        lo, rd = int_state.reg_lo, int_state.reg[self.d]
        rd.set_known_bits(lo.get_known_bits())
        rd.set_known_mask(lo.get_known_mask())
        rd.inc_version()
        return self
    def _str_bits(self):
        return "MFLO      %s" % (ri(self.d))
    def _repr_bits(self):
        return '%d' % (self.d)

class MTLO(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.s = s
    def get_int_reads(self): return 1 << self.s
    def update_int_state(self, int_state):
        rs, lo = int_state.reg[self.s], int_state.reg_lo
        lo.set_known_bits(rs.get_known_bits())
        lo.set_known_mask(rs.get_known_mask())
        lo.inc_version()
        return self
    def _str_bits(self):
        return "MTLO      %s" % (ri(self.s))
    def _repr_bits(self):
        return '%d' % (self.s)

class DSLLV(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.s = d, t, s
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        # A shift by 0 simply copies a value from one register into another.
        # The move may be into the very same register. Let OR figure it out,
        # and it may become a NOP.
        if self.s == 0: return OR(self.pc, self.opcode, self.d, self.t, 0).simplify()
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rd = int_state.reg[self.s], int_state.reg[self.d]
        if rs.is_known_mask(0x3F):
            rt, sa = int_state.reg[self.t], rs.get_known_bits(0x3F)
            known_bits = rt.get_known_bits() << sa
            known_mask = rt.get_known_mask() << sa
            # The lower 'a' bits are now also known to be unset.
            known_mask |= (1 << sa) - 1
            rd.set_known_bits(known_bits)
            rd.set_known_mask(known_mask)
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSLLV     %s, %s, %s" % (ri(self.d), ri(self.t), ri(self.s))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.s)

class DSRLV(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.s = d, t, s
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return OR(self.pc, self.opcode, self.d, self.t, 0).simplify()
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rd = int_state.reg[self.s], int_state.reg[self.d]
        if rs.is_known_mask(0x3F):
            rt, sa = int_state.reg[self.t], rs.get_known_bits(0x3F)
            known_bits = rt.get_known_bits() >> sa
            known_mask = rt.get_known_mask() >> sa
            # The upper 'a' bits are now also known to be unset.
            known_mask |= 0x10000000000000000 - (1 << (64 - sa))
            rd.set_known_bits(known_bits)
            rd.set_known_mask(known_mask)
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSRLV     %s, %s, %s" % (ri(self.d), ri(self.t), ri(self.s))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.s)

class DSRAV(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.s = d, t, s
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return OR(self.pc, self.opcode, self.d, self.t, 0).simplify()
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rd = int_state.reg[self.s], int_state.reg[self.d]
        if rs.is_known_mask(0x3F):
            rt, sa = int_state.reg[self.t], rs.get_known_bits(0x3F)
            known_bits = rt.get_known_bits() >> sa
            known_mask = rt.get_known_mask() >> sa
            # If bit 63 (which is now at bit 63 - a) was known, then all copies of
            # it are known. Otherwise, we don't know those bits anymore.
            if known_mask & (1 << (63 - sa)):
                known_bits = sign_extend_64(known_bits, 64 - sa)
                known_mask = sign_extend_64(known_mask, 64 - sa)
            rd.set_known_bits(known_bits)
            rd.set_known_mask(known_mask)
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSRAV     %s, %s, %s" % (ri(self.d), ri(self.t), ri(self.s))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.s)

class MULT(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if ((rs.is_known_mask(0xFFFFFFFF) and rs.get_known_bits(0xFFFFFFFF) == 0) or
            (rt.is_known_mask(0xFFFFFFFF) and rt.get_known_bits(0xFFFFFFFF) == 0)):
            hi.make_known(0)
            lo.make_known(0)
        elif rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = as_signed_32(rs.get_known_bits(0xFFFFFFFF)) * as_signed_32(rt.get_known_bits(0xFFFFFFFF))
            lo.make_known(sign_extend_64(result, 32))
            hi.make_known(sign_extend_64(as_unsigned_32(result >> 32), 32))
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "MULT      %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class MULTU(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if ((rs.is_known_mask(0xFFFFFFFF) and rs.get_known_bits(0xFFFFFFFF) == 0) or
            (rt.is_known_mask(0xFFFFFFFF) and rt.get_known_bits(0xFFFFFFFF) == 0)):
            hi.make_known(0)
            lo.make_known(0)
        elif rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) * rt.get_known_bits(0xFFFFFFFF)
            lo.make_known(sign_extend_64(result, 32))
            hi.make_known(sign_extend_64(result >> 32, 32))
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "MULTU     %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DIV(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if rt.is_known_mask(0xFFFFFFFF) and rt.get_known_bits(0xFFFFFFFF) == 0:
            # Undefined Behavior has been invoked!
            hi.make_unknown()
            lo.make_unknown()
        elif rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = as_signed_32(rs.get_known_bits(0xFFFFFFFF)) // as_signed_32(rt.get_known_bits(0xFFFFFFFF))
            lo.make_known(sign_extend_64(result, 32))
            hi.make_known(sign_extend_64(as_unsigned_32(result >> 32), 32))
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "DIV       %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DIVU(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if rt.is_known_mask(0xFFFFFFFF) and rt.get_known_bits(0xFFFFFFFF) == 0:
            # Undefined Behavior has been invoked!
            hi.make_unknown()
            lo.make_unknown()
        elif rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) // rt.get_known_bits(0xFFFFFFFF)
            lo.make_known(sign_extend_64(result, 32))
            hi.make_known(sign_extend_64(result >> 32, 32))
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "DIVU      %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DMULT(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if ((rs.is_known() and rs.get_known_bits() == 0) or
            (rt.is_known() and rt.get_known_bits() == 0)):
            hi.make_known(0)
            lo.make_known(0)
        elif rs.is_known() and rt.is_known():
            result = as_signed_64(rs.get_known_bits()) * as_signed_64(rt.get_known_bits())
            lo.make_known(result)
            hi.make_known(as_unsigned_64(result >> 64))
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "DMULT     %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DMULTU(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if ((rs.is_known() and rs.get_known_bits() == 0) or
            (rt.is_known() and rt.get_known_bits() == 0)):
            hi.make_known(0)
            lo.make_known(0)
        elif rs.is_known() and rt.is_known():
            result = rs.get_known_bits() * rt.get_known_bits()
            lo.make_known(result)
            hi.make_known(result >> 64)
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "DMULTU    %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DDIV(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if rt.is_known() and rt.get_known_bits() == 0:
            # Undefined Behavior has been invoked!
            hi.make_unknown()
            lo.make_unknown()
        elif rs.is_known() and rt.is_known():
            result = as_signed_64(rs.get_known_bits()) // as_signed_64(rt.get_known_bits())
            lo.make_known(result)
            hi.make_known(as_unsigned_64(result >> 64))
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "DDIV      %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DDIVU(NoExcept, NoIntWrites, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        hi, lo = int_state.reg_hi, int_state.reg_lo
        if rt.is_known() and rt.get_known_bits() == 0:
            # Undefined Behavior has been invoked!
            hi.make_unknown()
            lo.make_unknown()
        elif rs.is_known() and rt.is_known():
            result = rs.get_known_bits() // rt.get_known_bits()
            lo.make_known(result)
            hi.make_known(result >> 64)
        else:
            hi.make_unknown()
            lo.make_unknown()
        hi.inc_version()
        lo.inc_version()
        return self
    def _str_bits(self):
        return "DDIVU     %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class ADD(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        if self.t == 0: return ADDU(self.pc, self.opcode, self.d, self.s, 0)
        if self.s == self.t: return SLL(self.pc, self.opcode, self.d, self.s, 1)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        if rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) + rt.get_known_bits(0xFFFFFFFF)
            rd.make_known(sign_extend_64(result, 32))
        else:
            rd.make_unknown()
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "ADD       %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class ADDU(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return ADDU(self.pc, self.opcode, self.d, self.t, 0)
        if self.s == self.t: return SLL(self.pc, self.opcode, self.d, self.s, 1)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        # If all of the bits of both operands are known, and we're adding 0 to
        # something that was already sign-extended, turn it into a move.
        if rs.is_known() and rt.is_known():
            rs_bits, rt_bits = rs.get_known_bits(), rt.get_known_bits()
            if rs_bits == 0 and sign_extend_64(rt_bits, 32) == rt_bits:
                new_op = OR(self.pc, self.opcode, self.d, self.t, 0).simplify().copy_attributes(self)
            elif rt_bits == 0 and sign_extend_64(rs_bits, 32) == rs_bits:
                new_op = OR(self.pc, self.opcode, self.d, self.s, 0).simplify().copy_attributes(self)
        if rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) + rt.get_known_bits(0xFFFFFFFF)
            rd.make_known(sign_extend_64(result, 32))
        else:
            rd.make_unknown()
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "ADDU      %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SUB(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        # Suppress integer overflow checks for SUB between $0 and other
        # registers.
        if self.s == 0: return SUBU(self.pc, self.opcode, self.d, 0, self.t)
        if self.t == 0: return ADDU(self.pc, self.opcode, self.d, self.s, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        if rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) - rt.get_known_bits(0xFFFFFFFF)
            rd.make_known(sign_extend_64(as_unsigned_32(result), 32))
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "SUB       %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SUBU(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.t == 0: return ADDU(self.pc, self.opcode, self.d, self.s, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        if rs.is_known_mask(0xFFFFFFFF) and rt.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) - rt.get_known_bits(0xFFFFFFFF)
            rd.make_known(sign_extend_64(as_unsigned_32(result), 32))
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "SUBU      %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class AND(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == 0 or self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, self.s, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        rs_bits, rt_bits = rs.get_known_bits(), rt.get_known_bits()
        rs_mask, rt_mask = rs.get_known_mask(), rt.get_known_mask()
        # If all the bits of one operand are known, try to figure out if the
        # masking operation is superfluous. It is superfluous if an operand
        # that is fully known has 0s in at least the bits that are already
        # known to contain 0 in the other operand. The operation can then be
        # converted into a move from the other operand.
        if rs.is_known() and (~rs_bits & rt_mask) == ~rs_bits and (~rs_bits & rt_bits) == 0:
            simplify_notice("AND: Unset bits in $%d are already unset in $%d" % (self.s, self.t))
            new_op = OR(self.pc, self.opcode, self.d, self.t, 0).simplify().copy_attributes(self)
        elif rt.is_known() and (~rt_bits & rs_mask) == ~rt_bits and (~rt_bits & rs_bits) == 0:
            simplify_notice("AND: Unset bits in $%d are already unset in $%d" % (self.t, self.s))
            new_op = OR(self.pc, self.opcode, self.d, self.s, 0).simplify().copy_attributes(self)
        # For each bit position N, for inputs S and T and output D:
        # - if S[N] and T[N] are known to be 1, D[N] is known to be 1;
        # - if S[N] or T[N] is known to be 0, D[N] is known to be 0;
        # - otherwise, D[N] is unknown.
        # a) All bits known to be 1 in S and T are known to be 1 in D.
        rd_bits = rd_mask = rs_mask & rt_mask & rs_bits & rt_bits
        # b) All bits known to be 0 in S or T are known to be 0 in D.
        # XOR is used to implement this check across all 64 bits:
        # mask |  bit | result | notes
        # -----+------+--------+---------------------------------------------
        #    0 |    0 |      0 | the bit is unknown, so it stays unknown
        #    0 |    1 |      1 | this cannot happen: unknowns are 0 in 'bits'
        #    1 |    0 |      1 | this bit is known to be 0; so is the result
        #    1 |    1 |      0 | this bit is known to be 1; already decided
        rd_mask |= (rs_mask ^ rs_bits) | (rt_mask ^ rt_bits)
        rd.set_known_bits(rd_bits)
        rd.set_known_mask(rd_mask)
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "AND       %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class OR(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if (self.d == 0 or
            (self.d == self.s and self.t == 0) or
            (self.d == self.t and self.s == 0)):
            return NOP(self.pc, self.opcode)
        if self.t != 0 and (self.s == 0 or self.s == self.t):
            return OR(self.pc, self.opcode, self.d, self.t, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        rs_bits, rt_bits = rs.get_known_bits(), rt.get_known_bits()
        rs_mask, rt_mask = rs.get_known_mask(), rt.get_known_mask()
        # If all the bits of one operand are known, try to figure out if the
        # bit-set operation is superfluous. It is superfluous if an operand
        # that is fully known has 1s in at least the bits that are already
        # known to contain 1 in the other operand. The operation can then be
        # converted into a move from the other operand.
        if self.s != 0 and rs.is_known() and rs_bits & rt_mask & rt_bits == rs_bits:
            simplify_notice("OR: Set bits in $%d are already set in $%d" % (self.s, self.t))
            new_op = OR(self.pc, self.opcode, self.d, self.t, 0).simplify().copy_attributes(self)
        elif self.t != 0 and rt.is_known() and rt_bits & rs_mask & rs_bits == rt_bits:
            simplify_notice("OR: Set bits in $%d are already set in $%d" % (self.t, self.s))
            new_op = OR(self.pc, self.opcode, self.d, self.s, 0).simplify().copy_attributes(self)
        # For each bit position N, for inputs S and T and output D:
        # - if S[N] or T[N] is known to be 1, D[N] is known to be 1;
        # - if S[N] and T[N] are known to be 0, D[N] is known to be 0;
        # - otherwise, D[N] is unknown.
        # a) All bits known to be 1 in S or T are known to be 1 in D.
        rd_bits = rd_mask = (rs_bits & rs_mask) | (rt_bits & rt_mask)
        # b) All bits known to be 0 in S and T are known to be 0 in D.
        # mask |  bit | result | notes
        # -----+------+--------+---------------------------------------------
        #    0 |    0 |      0 | the bit is unknown, so it stays unknown
        #    0 |    1 |      1 | this cannot happen: unknowns are 0 in 'bits'
        #    1 |    0 |      1 | bits are known to be 0; so is the result
        #    1 |    1 |      0 | this bit is known to be 1; already decided
        rd_mask |= (rs_mask ^ rs_bits) & (rt_mask ^ rt_bits)
        rd.set_known_bits(rd_bits)
        rd.set_known_mask(rd_mask)
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "OR        %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class XOR(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return OR(self.pc, self.opcode, self.d, self.t, 0)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, self.s, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        # TODO Further analyse the values of the known bits.
        rd_bits = rs.get_known_bits() ^ rt.get_known_bits()
        rd_mask = rs.get_known_mask() & rt.get_known_mask()
        rd.set_known_bits(rd_bits)
        rd.set_known_mask(rd_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "XOR       %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class NOR(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t == 0: return ADDIU(self.pc, self.opcode, self.d, 0, -1)
        if self.s == self.t: return NOR(self.pc, self.opcode, self.d, self.s, 0)
        if self.s == 0: return NOR(self.pc, self.opcode, self.d, self.t, 0)
        if self.t == 0: return NOR(self.pc, self.opcode, self.d, self.s, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        # TODO Further analyse the values of the known bits.
        rd_bits = ~(rs.get_known_bits() | rt.get_known_bits())
        rd_mask = rs.get_known_mask() & rt.get_known_mask()
        rd.set_known_bits(rd_bits)
        rd.set_known_mask(rd_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "NOR       %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SLT(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        # SLT between the same register twice just loads the target register
        # with 0, as a register cannot be less than itself.
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        rs_bits, rt_bits = rs.get_known_bits(), rt.get_known_bits()
        rs_mask, rt_mask = rs.get_known_mask(), rt.get_known_mask()
        common_mask = rs_mask & rt_mask
        # Figure out how many bits are known at the top of both operands.
        if common_mask != 0xFFFFFFFFFFFFFFFF:
            common_bits, guess = 0, 32
            while guess > 0:
                guess_mask = 0x10000000000000000 - (1 << (64 - (common_bits + guess)))
                if common_mask & guess_mask == guess_mask:
                    common_bits += guess
                guess = guess >> 1
            common_mask = 0x10000000000000000 - (1 << (64 - common_bits))
        # If the top known bits of each register are unequal, we can figure
        # out the result of SLT (signed).
        if rs_bits & common_mask != rt_bits & common_mask:
            value = int(as_signed_64(rs_bits & common_mask) < as_signed_64(rt_bits & common_mask))
            simplify_notice("SLT: Comparison between $%d and $%d always yields %d" % (self.s, self.t, value))
            new_op = ORI(self.pc, self.opcode, self.d, 0, value).simplify().copy_attributes(self)
            rd.make_known(value)
        else:
            rd.set_known_bits(0)
            rd.set_known_mask(0xFFFFFFFFFFFFFFFE)
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "SLT       %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SLTU(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        # SLTU between the same register twice just loads the target register
        # with 0, as a register cannot be less than itself.
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        # SLTU between any register and $0 just loads the target register with
        # 0, as a register cannot be less than 0 (unsigned).
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        new_op = self
        rs_bits, rt_bits = rs.get_known_bits(), rt.get_known_bits()
        rs_mask, rt_mask = rs.get_known_mask(), rt.get_known_mask()
        common_mask = rs_mask & rt_mask
        # Figure out how many bits are known at the top of both operands.
        if common_mask != 0xFFFFFFFFFFFFFFFF:
            common_bits, guess = 0, 32
            while guess > 0:
                guess_mask = 0x10000000000000000 - (1 << (64 - (common_bits + guess)))
                if common_mask & guess_mask == guess_mask:
                    common_bits += guess
                guess = guess >> 1
            common_mask = 0x10000000000000000 - (1 << (64 - common_bits))
        # If the top known bits of each register are unequal, we can figure
        # out the result of SLTU (unsigned).
        if rs_bits & common_mask != rt_bits & common_mask:
            value = int(rs_bits & common_mask < rt_bits & common_mask)
            simplify_notice("SLTU: Comparison between $%d and $%d always yields %d" % (self.s, self.t, value))
            new_op = ORI(self.pc, self.opcode, self.d, 0, value).simplify().copy_attributes(self)
            rd.make_known(value)
        else:
            rd.set_known_bits(0)
            rd.set_known_mask(0xFFFFFFFFFFFFFFFE)
        rd.inc_version()
        return new_op
    def _str_bits(self):
        return "SLTU      %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class DADD(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return OR(self.pc, self.opcode, self.d, self.t, 0)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, self.s, 0)
        if self.s == self.t: return DSLL(self.pc, self.opcode, self.d, self.s, 1)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        if rs.is_known() and rt.is_known():
            result = rs.get_known_bits() + rt.get_known_bits()
            rd.make_known(result)
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DADD      %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class DADDU(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return OR(self.pc, self.opcode, self.d, self.t, 0)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, self.s, 0)
        if self.s == self.t: return DSLL(self.pc, self.opcode, self.d, self.s, 1)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        if rs.is_known() and rt.is_known():
            result = rs.get_known_bits() + rt.get_known_bits()
            rd.make_known(result)
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DADDU     %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class DSUB(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.s == 0: return DSUBU(self.pc, self.opcode, self.d, 0, self.t)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, self.s, 0).simplify()
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        if rs.is_known() and rt.is_known():
            result = rs.get_known_bits() - rt.get_known_bits()
            rd.make_known(as_unsigned_64(result))
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSUB      %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class DSUBU(NoExcept, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.s == self.t: return OR(self.pc, self.opcode, self.d, 0, 0)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, self.s, 0).simplify()
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rs, rt, rd = int_state.reg[self.s], int_state.reg[self.t], int_state.reg[self.d]
        if rs.is_known() and rt.is_known():
            result = rs.get_known_bits() - rt.get_known_bits()
            rd.make_known(as_unsigned_64(result))
        else:
            rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSUBU     %s, %s, %s" % (ri(self.d), ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class TEQ(NoIntWrites, NoIntState, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def _str_bits(self):
        return "TEQ       %s, %s" % (ri(self.s), ri(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class DSLL(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0 or self.a == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = rt.get_known_bits() << self.a
        known_mask = rt.get_known_mask() << self.a
        # The lower 'a' bits are now also known to be unset.
        known_mask |= (1 << self.a) - 1
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSLL      %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class DSRL(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0 or self.a == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = rt.get_known_bits() >> self.a
        known_mask = rt.get_known_mask() >> self.a
        # The upper 'a' bits are now also known to be unset.
        known_mask |= 0x10000000000000000 - (1 << (64 - self.a))
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSRL      %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class DSRA(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0 or self.a == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = rt.get_known_bits() >> self.a
        known_mask = rt.get_known_mask() >> self.a
        # If bit 63 (which is now at bit 63 - a) was known, then all copies of
        # it are known. Otherwise, we don't know those bits anymore.
        if known_mask & (1 << (63 - self.a)):
            known_bits = sign_extend_64(known_bits, 64 - self.a)
            known_mask = sign_extend_64(known_mask, 64 - self.a)
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSRA      %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class DSLL32(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = rt.get_known_bits() << (32 + self.a)
        known_mask = rt.get_known_mask() << (32 + self.a)
        # The lower 'a' bits are now also known to be unset.
        known_mask |= (1 << (32 + self.a)) - 1
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSLL32    %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class DSRL32(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = rt.get_known_bits() >> (32 + self.a)
        known_mask = rt.get_known_mask() >> (32 + self.a)
        # The upper 'a' bits are now also known to be unset.
        known_mask |= 0x10000000000000000 - (1 << (32 - self.a))
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSRL32    %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class DSRA32(NoExcept, Op):
    def __init__(self, pc, opcode, d, t, a):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.t, self.a = d, t, a
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        if self.t == 0: return OR(self.pc, self.opcode, self.d, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.t
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rt, rd = int_state.reg[self.t], int_state.reg[self.d]
        known_bits = rt.get_known_bits() >> (32 + self.a)
        known_mask = rt.get_known_mask() >> (32 + self.a)
        # If bit 63 (which is now at bit 63 - a) was known, then all copies of
        # it are known. Otherwise, we don't know those bits anymore.
        if known_mask & (1 << (31 - self.a)):
            known_bits = sign_extend_64(known_bits, 32 - self.a)
            known_mask = sign_extend_64(known_mask, 32 - self.a)
        rd.set_known_bits(known_bits)
        rd.set_known_mask(known_mask)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DSRA32    %s, %s, %d" % (ri(self.d), ri(self.t), self.a)
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.t, self.a)

class BLTZ(DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        # If a branch is to the instruction straight after the delay slot,
        # the delay slot is resolved just before the following instruction
        # is. It's just as if the branch was not even there to begin with.
        # This also goes for all other branches, except for Branch Likely,
        # and except for Branch And Link which always updates $31.
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self): return 1 << self.s
    def update_int_state(self, int_state):
        rs = int_state.reg[self.s]
        new_op = self
        if rs.is_known_mask(0x8000000000000000):
            if rs.get_known_bits(0x8000000000000000) == 0x8000000000000000:
                simplify_notice("BLTZ: Branch always taken")
                new_op = B(self.pc, self.opcode, self.joffset)
            else:
                simplify_notice("BLTZ: Branch never taken")
                new_op = NOP(self.pc, self.opcode)
        return new_op
    def _str_bits(self):
        return "BLTZ      %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BGEZ(DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self): return 1 << self.s
    def update_int_state(self, int_state):
        rs = int_state.reg[self.s]
        new_op = self
        if self.s != 0 and rs.is_known_mask(0x8000000000000000):
            if rs.get_known_bits(0x8000000000000000) == 0:
                if self.s != 0: simplify_notice("BGEZ: Branch always taken")
                new_op = B(self.pc, self.opcode, self.joffset)
            else:
                simplify_notice("BGEZ: Branch never taken")
                new_op = NOP(self.pc, self.opcode)
        return new_op
    def _str_bits(self):
        return "BGEZ      %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BLTZL(DSBranchLikely, DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BLTZL     %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BGEZL(DSBranchLikely, DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        if self.s == 0: return B(self.pc, self.opcode, self.joffset)  # $0 == 0, therefore $0 >= 0
        return self
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BGEZL     %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BLTZAL(DSBranchLink31, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def get_int_reads(self): return 1 << self.s
    def update_int_state(self, int_state):
        rs = int_state.reg[self.s]
        new_op = self
        if rs.is_known_mask(0x8000000000000000):
            if rs.get_known_bits(0x8000000000000000) == 0x8000000000000000:
                simplify_notice("BLTZAL: Branch always taken")
                new_op = BAL(self.pc, self.opcode, self.joffset)
            # else: Can't kill this instruction, as $31 must be written.
        return new_op
    def _str_bits(self):
        return "BLTZAL    %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BGEZAL(DSBranchLink31, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def get_int_reads(self): return 1 << self.s
    def update_int_state(self, int_state):
        rs = int_state.reg[self.s]
        new_op = self
        if self.s != 0 and rs.is_known_mask(0x8000000000000000):
            if rs.get_known_bits(0x8000000000000000) == 0:
                if self.s != 0: simplify_notice("BGEZAL: Branch always taken")
                new_op = BAL(self.pc, self.opcode, self.joffset)
            # else: Can't kill this instruction, as $31 must be written.
        return new_op
    def _str_bits(self):
        return "BGEZAL    %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BLTZALL(DSBranchLikely, DSBranchLink31, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BLTZALL   %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BGEZALL(DSBranchLikely, DSBranchLink31, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        if self.s == 0: return BAL(self.pc, self.opcode, self.joffset)  # $0 == 0, therefore $0 >= 0
        return self
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BGEZALL   %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class J(NoIntReads, DSBranch, Op):
    def __init__(self, pc, opcode, jabs):
        super(self.__class__, self).__init__(pc, opcode)
        self.jabs = jabs
    def simplify(self):
        if ((self.pc + 4) & 0xF0000000) | (self.jabs << 2) == self.pc + 8: return NOP(self.pc, self.opcode)
        return self
    def _str_bits(self):
        return "J         %s" % (jabs(self.pc, self.jabs))
    def _repr_bits(self):
        return '0x%08X' % (self.jabs)

class JAL(NoIntReads, DSBranchLink31, Op):
    def __init__(self, pc, opcode, jabs):
        super(self.__class__, self).__init__(pc, opcode)
        self.jabs = jabs
    def _str_bits(self):
        return "JAL       %s" % (jabs(self.pc, self.jabs))
    def _repr_bits(self):
        return '0x%08X' % (self.jabs)

class BEQ(DSBranch, Op):
    def __init__(self, pc, opcode, s, t, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t, self.joffset = s, t, joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        if self.s == self.t: return B(self.pc, self.opcode, self.joffset)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        new_op = self
        if rs.is_known() and rt.is_known() and rs.get_known_bits() == rt.get_known_bits():
            if not (self.s == self.t == 0): simplify_notice("BEQ: Branch always taken")
            new_op = B(self.pc, self.opcode, self.joffset)
        else:
            common_mask = rs.get_known_mask() & rt.get_known_mask()
            if rs.get_known_bits() & common_mask != rt.get_known_bits() & common_mask:
                simplify_notice("BEQ: Branch never taken")
                new_op = NOP(self.pc, self.opcode)
        return new_op
    def _str_bits(self):
        return "BEQ       %s, %s, %s" % (ri(self.s), ri(self.t), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.t, self.joffset)

class BNE(DSBranch, Op):
    def __init__(self, pc, opcode, s, t, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t, self.joffset = s, t, joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        new_op = self
        if rs.is_known() and rt.is_known() and rs.get_known_bits() == rt.get_known_bits():
            simplify_notice("BNE: Branch never taken")
            new_op = NOP(self.pc, self.opcode)
        else:
            common_mask = rs.get_known_mask() & rt.get_known_mask()
            if rs.get_known_bits() & common_mask != rt.get_known_bits() & common_mask:
                simplify_notice("BNE: Branch always taken")
                new_op = B(self.pc, self.opcode, self.joffset)
        return new_op
    def _str_bits(self):
        return "BNE       %s, %s, %s" % (ri(self.s), ri(self.t), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.t, self.joffset)

class BLEZ(DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        if self.s == 0: return B(self.pc, self.opcode, self.joffset)  # $0 == 0, therefore $0 <= 0
        return self
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BLEZ      %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BGTZ(DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BGTZ      %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class ADDI(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.s == 0: return ADDIU(self.pc, self.opcode, self.t, 0, self.imm).simplify()
        if self.imm == 0: return ADDU(self.pc, self.opcode, self.t, self.s, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        if rs.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) + self.imm
            rt.make_known(sign_extend_64(as_unsigned_32(result), 32))
        else:
            rt.make_unknown()
        rt.inc_version()
        return self
    def _str_bits(self):
        return "ADDI      %s, %s, %s" % (ri(self.t), ri(self.s), imm16s(self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.t, self.s, self.imm)

class ADDIU(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.s == self.imm == 0: return OR(self.pc, self.opcode, self.t, 0, 0)
        if self.s == 0 and self.imm > 0: return ORI(self.pc, self.opcode, self.t, 0, self.imm)
        if self.imm == 0: return ADDU(self.pc, self.opcode, self.t, self.s, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        if rs.is_known_mask(0xFFFFFFFF):
            result = rs.get_known_bits(0xFFFFFFFF) + self.imm
            rt.make_known(sign_extend_64(as_unsigned_32(result), 32))
        else:
            rt.make_unknown()
        rt.inc_version()
        return self
    def _str_bits(self):
        return "ADDIU     %s, %s, %s" % (ri(self.t), ri(self.s), imm16s(self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.t, self.s, self.imm)

class SLTI(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        # SLT between 0 and negative or 0 simply load a register with 0.
        # SLT between 0 and positive simply load a register with 1.
        if self.s == 0 and self.imm <= 0: return OR(self.pc, self.opcode, self.t, 0, 0)
        if self.s == 0 and self.imm > 0: return ORI(self.pc, self.opcode, self.t, 0, 1)
        if self.imm == 0: return SLT(self.pc, self.opcode, self.t, self.s, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        # TODO Analyse the values of the known bits.
        rt.set_known_bits(0)
        rt.set_known_mask(0xFFFFFFFFFFFFFFFE)
        rt.inc_version()
        return self
    def _str_bits(self):
        return "SLTI      %s, %s, %s" % (ri(self.t), ri(self.s), imm16s(self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.t, self.s, self.imm)

class SLTIU(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        # SLT between 0 and 0 simply loads a register with 0.
        # SLT between 0 and negative (large positive as unsigned) or positive
        # simply load a register with 1.
        if self.s == 0 and self.imm == 0: return OR(self.pc, self.opcode, self.t, 0, 0)
        if self.s == 0 and self.imm != 0: return ORI(self.pc, self.opcode, self.t, 0, 1)
        if self.imm == 0: return SLTU(self.pc, self.opcode, self.t, self.s, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        # TODO Analyse the values of the known bits.
        rt.set_known_bits(0)
        rt.set_known_mask(0xFFFFFFFFFFFFFFFE)
        rt.inc_version()
        return self
    def _str_bits(self):
        return "SLTIU     %s, %s, %s" % (ri(self.t), ri(self.s), imm16s(self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.t, self.s, self.imm)

class ANDI(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.s == 0 or self.imm == 0: return OR(self.pc, self.opcode, self.t, 0, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        new_op = self
        rs_bits, rs_mask = rs.get_known_bits(), rs.get_known_mask()
        # Try to figure out if the masking operation is superfluous. It is
        # superfluous if the register operand is known to have 0s in at least
        # the bits that contain 0 in the immediate, zero-extended to 64 bits.
        # The operation can then be converted into a move from the register
        # operand.
        if (~self.imm & rs_mask) == ~self.imm & 0xFFFFFFFFFFFFFFFF and (~self.imm & rs_bits) == 0:
            simplify_notice("ANDI: Unset bits in 0x%04X are already unset in $%d" % (self.imm, self.s))
            new_op = OR(self.pc, self.opcode, self.t, self.s, 0).simplify().copy_attributes(self)
        # For each bit position N, for inputs S and I and output T:
        # - if S[N] and I[N] are known to be 1, T[N] is known to be 1;
        # - if S[N] or I[N] is known to be 0, T[N] is known to be 0;
        # - otherwise, T[N] is unknown.
        # a) All bits known to be 1 in S and T are known to be 1 in T.
        rt_bits = rt_mask = rs_mask & rs_bits & self.imm & 0xFFFFFFFFFFFFFFFF
        # b) All bits known to be 0 in S or I are known to be 0 in T.
        # XOR is used to implement this check across all 64 bits:
        # mask |  bit | result | notes
        # -----+------+--------+---------------------------------------------
        #    0 |    0 |      0 | the bit is unknown, so it stays unknown
        #    0 |    1 |      1 | this cannot happen: unknowns are 0 in 'bits'
        #    1 |    0 |      1 | this bit is known to be 0; so is the result
        #    1 |    1 |      0 | this bit is known to be 1; already decided
        rt_mask |= (rs_mask ^ rs_bits) | (0xFFFFFFFFFFFFFFFF ^ self.imm)
        rt.set_known_bits(rt_bits)
        rt.set_known_mask(rt_mask)
        rt.inc_version()
        return new_op
    def _str_bits(self):
        return "ANDI      %s, %s, %s" % (ri(self.t), ri(self.s), imm16u(self.imm))
    def _repr_bits(self):
        return '%d, %d, 0x%4X' % (self.t, self.s, self.imm)

class ORI(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.imm == 0: return OR(self.pc, self.opcode, self.t, self.s, 0).simplify()
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        new_op = self
        # If all the bits that would be set by this ORI are already known to
        # be 1 in the source register, this is a move.
        if rs.is_known_mask(self.imm) and rs.get_known_bits(self.imm) == self.imm:
            simplify_notice("ORI: Set bits in 0x%04X are already set in $%d" % (self.imm, self.s))
            new_op = OR(self.pc, self.opcode, self.t, self.s, 0).copy_attributes(self)
        if rs.is_known():
            rt.make_known(rs.get_known_bits() | self.imm)
        else:
            # Every set bit in the mask is now known to be 1 in the
            # destination register.
            rt.set_known_bits(rs.get_known_bits() | self.imm)
            rt.set_known_mask(rs.get_known_mask() | self.imm)
        rt.inc_version()
        return new_op
    def _str_bits(self):
        return "ORI       %s, %s, %s" % (ri(self.t), ri(self.s), imm16u(self.imm))
    def _repr_bits(self):
        return '%d, %d, 0x%4X' % (self.t, self.s, self.imm)

class XORI(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.s == 0: return ORI(self.pc, self.opcode, self.t, 0, self.imm).simplify()
        if self.imm == 0: return OR(self.pc, self.opcode, self.t, self.s, 0).simplify()
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt, = int_state.reg[self.s], int_state.reg[self.t]
        # TODO Analyse the values of the known bits.
        rt.set_known_bits(rs.get_known_bits() ^ self.imm)
        rt.set_known_mask(rs.get_known_mask())
        rt.inc_version()
        return self
    def _str_bits(self):
        return "XORI      %s, %s, %s" % (ri(self.t), ri(self.s), imm16u(self.imm))
    def _repr_bits(self):
        return '%d, %d, 0x%4X' % (self.t, self.s, self.imm)

class LUI(NoExcept, NoIntReads, Op):
    def __init__(self, pc, opcode, t, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.imm = t, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.imm == 0: return OR(self.pc, self.opcode, self.t, 0, 0)
        return self
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rt = int_state.reg[self.t]
        if rt.is_known() and rt.get_known_bits() == sign_extend_64(self.imm << 16, 32):
            simplify_notice("LUI: $%d already has the value 0x%08X" % (self.t, as_unsigned_32(self.imm << 16)))
            new_op = NOP(self.pc, self.opcode).copy_attributes(self)
            return new_op
        rt.make_known(sign_extend_64(self.imm << 16, 32))
        rt.inc_version()
        return self
    def _str_bits(self):
        return "LUI       %s, %s" % (ri(self.t), imm16u(as_unsigned_16(self.imm)))
    def _repr_bits(self):
        return '%d, %d' % (self.t, self.imm)

class MFC0(NoIntReads, Op):
    def __init__(self, pc, opcode, d, c0reg):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.c0reg = d, c0reg
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "MFC0      %s, %s" % (ri(self.d), rc0(self.c0reg))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.c0reg)

class MTC0(NoIntWrites, NoIntState, Op):
    def __init__(self, pc, opcode, c0reg, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.c0reg, self.s = c0reg, s
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "MTC0      %s, %s" % (ri(self.s), rc0(self.c0reg))
    def _repr_bits(self):
        return '%d, %d' % (self.c0reg, self.s)

class TLBR(NoInt, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "TLBR"
    def _repr_bits(self):
        return ''

class TLBWI(NoInt, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "TLBWI"
    def _repr_bits(self):
        return ''

class TLBWR(NoInt, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "TLBWR"
    def _repr_bits(self):
        return ''

class TLBP(NoInt, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "TLBP"
    def _repr_bits(self):
        return ''

class ERET(NoInt, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "ERET"
    def _repr_bits(self):
        return ''

class MFC1(NoIntReads, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, c1reg):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.c1reg = d, c1reg
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "MFC1      %s, %s" % (ri(self.d), rc1(self.c1reg))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.c1reg)

class DMFC1(NoIntReads, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, c1reg):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.c1reg = d, c1reg
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "DMFC1     %s, %s" % (ri(self.d), rc1(self.c1reg))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.c1reg)

class CFC1(NoIntReads, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, c1reg):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.c1reg = d, c1reg
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.d
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "CFC1      %s, %s" % (ri(self.d), rc1c(self.c1reg))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.c1reg)

class MTC1(NoIntWrites, NoIntState, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, c1reg, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.c1reg, self.s = c1reg, s
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "MTC1      %s, %s" % (ri(self.s), rc1(self.c1reg))
    def _repr_bits(self):
        return '%d, %d' % (self.c1reg, self.s)

class DMTC1(NoIntWrites, NoIntState, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, c1reg, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.c1reg, self.s = c1reg, s
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "DMTC1     %s, %s" % (ri(self.s), rc1(self.c1reg))
    def _repr_bits(self):
        return '%d, %d' % (self.c1reg, self.s)

class CTC1(NoIntWrites, NoIntState, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, c1reg, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.c1reg, self.s = c1reg, s
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "CTC1      %s, %s" % (ri(self.s), rc1c(self.c1reg))
    def _repr_bits(self):
        return '%d, %d' % (self.c1reg, self.s)

class BC1F(NoInt, DSBranch, Cop1, Op):
    def __init__(self, pc, opcode, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.joffset = joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        return self
    def _str_bits(self):
        return "BC1F      %s" % (joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d' % (self.joffset)

class BC1T(NoInt, DSBranch, Cop1, Op):
    def __init__(self, pc, opcode, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.joffset = joffset
    def simplify(self):
        if self.joffset == +1: return NOP(self.pc, self.opcode)
        return self
    def _str_bits(self):
        return "BC1T      %s" % (joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d' % (self.joffset)

class BC1FL(NoInt, DSBranchLikely, DSBranch, Cop1, Op):
    def __init__(self, pc, opcode, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.joffset = joffset
    def _str_bits(self):
        return "BC1FL     %s" % (joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d' % (self.joffset)

class BC1TL(NoInt, DSBranchLikely, DSBranch, Cop1, Op):
    def __init__(self, pc, opcode, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.joffset = joffset
    def _str_bits(self):
        return "BC1TL     %s" % (joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d' % (self.joffset)

class ADD_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "ADD.S     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SUB_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "SUB.S     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class MUL_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "MUL.S     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class DIV_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "DIV.S     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SQRT_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "SQRT.S    %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class ABS_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "ABS.S     %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class MOV_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def simplify(self):
        # MOV.S is not an arithmetic operation; it only transfers bits from
        # one register to another. It doesn't change the type of data found
        # in the register. Therefore, "moving" from one register into itself
        # does not really do anything.
        # MOV.S is supposed to raise a Coprocessor Unusable exception if
        # Coprocessor 1 is not currently usable, but a self-move does not
        # really matter enough to invoke the Coprocessor Unusable exception,
        # possibly to restore the current thread's floating-point context.
        # Leave it to a later instruction to check for it, because this one
        # is now NOP.
        if self.d == self.s: return NOP(self.pc, self.opcode)
        return self
    def _str_bits(self):
        return "MOV.S     %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class NEG_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "NEG.S     %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class ROUND_L_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "ROUND.L.S %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class TRUNC_L_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "TRUNC.L.S %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CEIL_L_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CEIL.L.S  %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class FLOOR_L_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "FLOOR.L.S %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class ROUND_W_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "ROUND.W.S %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class TRUNC_W_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "TRUNC.W.S %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CEIL_W_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CEIL.W.S  %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class FLOOR_W_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "FLOOR.W.S %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_D_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.D.S   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_W_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.W.S   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_L_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.L.S   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class C_F_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.F.S     %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_UN_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.UN.S    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_EQ_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.EQ.S    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_UEQ_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.UEQ.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_OLT_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.OLT.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_ULT_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.ULT.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_OLE_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.OLE.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_ULE_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.ULE.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_SF_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.SF.S    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGLE_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGLE.S  %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_SEQ_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.SEQ.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGL_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGL.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_LT_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.LT.S    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGE_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGE.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_LE_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.LE.S    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGT_S(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGT.S   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class ADD_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "ADD.D     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SUB_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "SUB.D     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class MUL_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "MUL.D     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class DIV_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s, self.t = d, s, t
    def _str_bits(self):
        return "DIV.D     %s, %s, %s" % (rc1(self.d), rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.s, self.t)

class SQRT_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "SQRT.D    %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class ABS_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "ABS.D     %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class MOV_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def simplify(self):
        if self.d == self.s: return NOP(self.pc, self.opcode)
        return self
    def _str_bits(self):
        return "MOV.D     %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class NEG_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "NEG.D     %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class ROUND_L_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "ROUND.L.D %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class TRUNC_L_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "TRUNC.L.D %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CEIL_L_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CEIL.L.D  %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class FLOOR_L_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "FLOOR.L.D %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class ROUND_W_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "ROUND.W.D %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class TRUNC_W_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "TRUNC.W.D %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CEIL_W_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CEIL.W.D  %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class FLOOR_W_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "FLOOR.W.D %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_S_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.S.D   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_W_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.W.D   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_L_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.L.D   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class C_F_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.F.D     %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_UN_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.UN.D    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_EQ_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.EQ.D    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_UEQ_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.UEQ.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_OLT_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.OLT.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_ULT_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.ULT.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_OLE_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.OLE.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_ULE_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.ULE.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_SF_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.SF.D    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGLE_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGLE.D  %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_SEQ_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.SEQ.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGL_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGL.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_LT_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.LT.D    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGE_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGE.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_LE_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.LE.D    %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class C_NGT_D(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, s, t):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t = s, t
    def _str_bits(self):
        return "C.NGT.D   %s, %s" % (rc1(self.s), rc1(self.t))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.t)

class CVT_S_W(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.S.W   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_D_W(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.D.W   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_S_L(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.S.L   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class CVT_D_L(NoInt, NoExcept, Cop1, Op):
    def __init__(self, pc, opcode, d, s):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.s = d, s
    def _str_bits(self):
        return "CVT.D.L   %s, %s" % (rc1(self.d), rc1(self.s))
    def _repr_bits(self):
        return '%d, %d' % (self.d, self.s)

class BEQL(DSBranchLikely, DSBranch, Op):
    def __init__(self, pc, opcode, s, t, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t, self.joffset = s, t, joffset
    def simplify(self):
        if self.s == self.t: return B(self.pc, self.opcode, self.joffset)
        return self
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def _str_bits(self):
        return "BEQL      %s, %s, %s" % (ri(self.s), ri(self.t), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.t, self.joffset)

class BNEL(DSBranchLikely, DSBranch, Op):
    def __init__(self, pc, opcode, s, t, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.t, self.joffset = s, t, joffset
    def get_int_reads(self): return (1 << self.s) | (1 << self.t)
    def _str_bits(self):
        return "BNEL      %s, %s, %s" % (ri(self.s), ri(self.t), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.t, self.joffset)

class BLEZL(DSBranchLikely, DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def simplify(self):
        if self.s == 0: return B(self.pc, self.opcode, self.joffset)  # $0 == 0, therefore $0 <= 0
        return self
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BLEZL     %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class BGTZL(DSBranchLikely, DSBranch, Op):
    def __init__(self, pc, opcode, s, joffset):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.joffset = s, joffset
    def get_int_reads(self): return 1 << self.s
    def _str_bits(self):
        return "BGTZL     %s, %s" % (ri(self.s), joffset(self.pc, self.joffset))
    def _repr_bits(self):
        return '%d, %d' % (self.s, self.joffset)

class DADDI(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.s == 0: return ADDIU(self.pc, self.opcode, self.t, 0, self.imm).simplify()
        if self.imm == 0: return OR(self.pc, self.opcode, self.t, self.s, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        if rs.is_known():
            result = rs.get_known_bits() + self.imm
            rt.make_known(as_unsigned_64(result))
        else:
            rt.make_unknown()
        rt.inc_version()
        return self
    def _str_bits(self):
        return "DADDI     %s, %s, %s" % (ri(self.t), ri(self.s), imm16s(self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.t, self.s, self.imm)

class DADDIU(NoExcept, Op):
    def __init__(self, pc, opcode, t, s, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.t, self.s, self.imm = t, s, imm
    def simplify(self):
        if self.t == 0: return NOP(self.pc, self.opcode)
        if self.s == 0: return ADDIU(self.pc, self.opcode, self.t, 0, self.imm).simplify()
        if self.imm == 0: return OR(self.pc, self.opcode, self.t, self.s, 0)
        return self
    def get_int_reads(self): return 1 << self.s
    def get_int_writes(self): return 1 << self.t
    def update_int_state(self, int_state):
        rs, rt = int_state.reg[self.s], int_state.reg[self.t]
        if rs.is_known():
            result = rs.get_known_bits() + self.imm
            rt.make_known(as_unsigned_64(result))
        else:
            rt.make_unknown()
        rt.inc_version()
        return self
    def _str_bits(self):
        return "DADDIU    %s, %s, %s" % (ri(self.t), ri(self.s), imm16s(self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.t, self.s, self.imm)

class LDL(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self):
        # LDL reads part of the source register in order to preserve the
        # rightmost bytes.
        return (1 << self.addr_reg) | (1 << self.d)
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LDL       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LDR(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self):
        # LDR reads part of the source register in order to preserve the
        # leftmost bytes.
        return (1 << self.addr_reg) | (1 << self.d)
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LDR       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LB(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LB        %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LH(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LH        %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LWL(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self):
        # LWL reads part of the source register in order to preserve the
        # rightmost bytes.
        return (1 << self.addr_reg) | (1 << self.d)
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LWL       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LW(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LW        %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LBU(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.set_known_bits(0)
        rd.set_known_mask(0xFFFFFFFFFFFFFF00)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LBU       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LHU(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.set_known_bits(0)
        rd.set_known_mask(0xFFFFFFFFFFFF0000)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LHU       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LWR(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_reads(self):
        # LWR reads part of the source register in order to preserve the
        # leftmost bytes.
        return (1 << self.addr_reg) | (1 << self.d)
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LWR       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LWU(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.set_known_bits(0)
        rd.set_known_mask(0xFFFFFFFF00000000)
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LWU       %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class SB(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SB        %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SH(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SH        %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SWL(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SWL       %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SW(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SW        %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SDL(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SDL       %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SDR(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SDR       %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SWR(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SWR       %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class CACHE(NoInt, NoExcept, Op):
    def __init__(self, pc, opcode, cache_op, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.cache_op, self.addr_reg, self.imm = cache_op, addr_reg, imm
    def _str_bits(self):
        return "CACHE     %s, %s" % (cache(self.cache_op), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.cache_op, self.addr_reg, self.imm)

class LL(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LL        %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LWC1(LoadCop1Offset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def _str_bits(self):
        return "LWC1      %s, %s" % (rc1(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LDC1(LoadCop1Offset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def _str_bits(self):
        return "LDC1      %s, %s" % (rc1(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class LD(LoadIntOffset, Op):
    def __init__(self, pc, opcode, d, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.d, self.addr_reg, self.imm = d, addr_reg, imm
    def simplify(self):
        if self.d == 0: return NOP(self.pc, self.opcode)
        return self
    def update_int_state(self, int_state):
        rd = int_state.reg[self.d]
        rd.make_unknown()
        rd.inc_version()
        return self
    def _str_bits(self):
        return "LD        %s, %s" % (ri(self.d), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.d, self.addr_reg, self.imm)

class SC(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def simplify(self):
        if self.s == 0: return NOP(self.pc, self.opcode)
        return self
    def get_int_writes(self): return 1 << self.s
    def update_int_state(self, int_state):
        rt = int_state.reg[self.s]
        # SC sets the source data register to 0 or 1 according to whether it
        # successfully linked with the previous LL.
        rt.set_known_bits(0)
        rt.set_known_mask(0xFFFFFFFFFFFFFFFE)
        rt.inc_version()
        return self
    def _str_bits(self):
        return "SC        %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SWC1(StoreCop1Offset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SWC1      %s, %s" % (rc1(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SDC1(StoreCop1Offset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SDC1      %s, %s" % (rc1(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class SD(StoreIntOffset, Op):
    def __init__(self, pc, opcode, s, addr_reg, imm):
        super(self.__class__, self).__init__(pc, opcode)
        self.s, self.addr_reg, self.imm = s, addr_reg, imm
    def _str_bits(self):
        return "SD        %s, %s" % (ri(self.s), memri16(self.addr_reg, self.imm))
    def _repr_bits(self):
        return '%d, %d, %d' % (self.s, self.addr_reg, self.imm)

class Unknown(NoInt, Op):
    def __init__(self, pc, opcode):
        super(self.__class__, self).__init__(pc, opcode)
    def _str_bits(self):
        return "???"
    def _repr_bits(self):
        return ''

class OpcodeParser:
    def __init__(self, opcode):
        self.opcode = opcode
    def __getattr__(self, name):
        if   name == 'opcode':  return self.opcode
        elif name == 'major':   return (self.opcode >> 26) & 0x3F
        elif name == 'special': return self.opcode & 0x3F
        elif name == 'regimm':  return (self.opcode >> 16) & 0x1F
        elif name == 'cop':     return (self.opcode >> 21) & 0x1F
        elif name == 'tlb':     return self.opcode & 0x3F
        elif name == 'c1cond':  return (self.opcode >> 16) & 0x3
        elif name == 'c1':      return self.opcode & 0x3F
        elif name == 'rd':      return (self.opcode >> 11) & 0x1F
        elif name == 'rs':      return (self.opcode >> 21) & 0x1F
        elif name == 'rt':      return (self.opcode >> 16) & 0x1F
        elif name == 'sa':      return (self.opcode >>  6) & 0x1F
        elif name == 'imm16u':  return self.opcode & 0xFFFF
        elif name == 'imm16s':  return -0x10000 + (self.opcode & 0xFFFF) if (self.opcode & 0xFFFF) >= 0x8000 else self.opcode & 0xFFFF
        elif name == 'fd':      return (self.opcode >>  6) & 0x1F
        elif name == 'fs':      return (self.opcode >> 11) & 0x1F
        elif name == 'ft':      return (self.opcode >> 16) & 0x1F
        elif name == 'imm26':   return self.opcode & 0x3FFFFFF
        elif name == 'excode':  return (self.opcode >> 6) & 0xFFFFF
        else:                   raise AttributeError(name)
    def __str__(self):
        return "0x%08X" % (self.opcode)
    def __repr__(self):
        return '%s(0x%08X)' % (self.__class__.__name__, self.opcode)

special = {
    0: lambda pc, op: SLL(pc, op.opcode, op.rd, op.rt, op.sa),
    2: lambda pc, op: SRL(pc, op.opcode, op.rd, op.rt, op.sa),
    3: lambda pc, op: SRA(pc, op.opcode, op.rd, op.rt, op.sa),
    4: lambda pc, op: SLLV(pc, op.opcode, op.rd, op.rt, op.rs),
    6: lambda pc, op: SRLV(pc, op.opcode, op.rd, op.rt, op.rs),
    7: lambda pc, op: SRAV(pc, op.opcode, op.rd, op.rt, op.rs),
    8: lambda pc, op: JR(pc, op.opcode, op.rs),
    9: lambda pc, op: JALR(pc, op.opcode, op.rs, op.rd),
    12: lambda pc, op: SYSCALL(pc, op.opcode, op.excode),
    13: lambda pc, op: BREAK(pc, op.opcode, op.excode),
    15: lambda pc, op: SYNC(pc, op.opcode),
    16: lambda pc, op: MFHI(pc, op.opcode, op.rd),
    17: lambda pc, op: MTHI(pc, op.opcode, op.rs),
    18: lambda pc, op: MFLO(pc, op.opcode, op.rd),
    19: lambda pc, op: MTLO(pc, op.opcode, op.rs),
    20: lambda pc, op: DSLLV(pc, op.opcode, op.rd, op.rt, op.rs),
    22: lambda pc, op: DSRLV(pc, op.opcode, op.rd, op.rt, op.rs),
    23: lambda pc, op: DSRAV(pc, op.opcode, op.rd, op.rt, op.rs),
    24: lambda pc, op: MULT(pc, op.opcode, op.rs, op.rt),
    25: lambda pc, op: MULTU(pc, op.opcode, op.rs, op.rt),
    26: lambda pc, op: DIV(pc, op.opcode, op.rs, op.rt),
    27: lambda pc, op: DIVU(pc, op.opcode, op.rs, op.rt),
    28: lambda pc, op: DMULT(pc, op.opcode, op.rs, op.rt),
    29: lambda pc, op: DMULTU(pc, op.opcode, op.rs, op.rt),
    30: lambda pc, op: DDIV(pc, op.opcode, op.rs, op.rt),
    31: lambda pc, op: DDIVU(pc, op.opcode, op.rs, op.rt),
    32: lambda pc, op: ADD(pc, op.opcode, op.rd, op.rs, op.rt),
    33: lambda pc, op: ADDU(pc, op.opcode, op.rd, op.rs, op.rt),
    34: lambda pc, op: SUB(pc, op.opcode, op.rd, op.rs, op.rt),
    35: lambda pc, op: SUBU(pc, op.opcode, op.rd, op.rs, op.rt),
    36: lambda pc, op: AND(pc, op.opcode, op.rd, op.rs, op.rt),
    37: lambda pc, op: OR(pc, op.opcode, op.rd, op.rs, op.rt),
    38: lambda pc, op: XOR(pc, op.opcode, op.rd, op.rs, op.rt),
    39: lambda pc, op: NOR(pc, op.opcode, op.rd, op.rs, op.rt),
    42: lambda pc, op: SLT(pc, op.opcode, op.rd, op.rs, op.rt),
    43: lambda pc, op: SLTU(pc, op.opcode, op.rd, op.rs, op.rt),
    44: lambda pc, op: DADD(pc, op.opcode, op.rd, op.rs, op.rt),
    45: lambda pc, op: DADDU(pc, op.opcode, op.rd, op.rs, op.rt),
    46: lambda pc, op: DSUB(pc, op.opcode, op.rd, op.rs, op.rt),
    47: lambda pc, op: DSUBU(pc, op.opcode, op.rd, op.rs, op.rt),
    52: lambda pc, op: TEQ(pc, op.opcode, op.rs, op.rt),
    56: lambda pc, op: DSLL(pc, op.opcode, op.rd, op.rt, op.sa),
    58: lambda pc, op: DSRL(pc, op.opcode, op.rd, op.rt, op.sa),
    59: lambda pc, op: DSRA(pc, op.opcode, op.rd, op.rt, op.sa),
    60: lambda pc, op: DSLL32(pc, op.opcode, op.rd, op.rt, op.sa),
    62: lambda pc, op: DSRL32(pc, op.opcode, op.rd, op.rt, op.sa),
    63: lambda pc, op: DSRA32(pc, op.opcode, op.rd, op.rt, op.sa),
}

def disassemble_special(pc, op):
    return special.get(op.special, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

regimm = {
    0: lambda pc, op: BLTZ(pc, op.opcode, op.rs, op.imm16s),
    1: lambda pc, op: BGEZ(pc, op.opcode, op.rs, op.imm16s),
    2: lambda pc, op: BLTZL(pc, op.opcode, op.rs, op.imm16s),
    3: lambda pc, op: BGEZL(pc, op.opcode, op.rs, op.imm16s),
    16: lambda pc, op: BLTZAL(pc, op.opcode, op.rs, op.imm16s),
    17: lambda pc, op: BGEZAL(pc, op.opcode, op.rs, op.imm16s),
    18: lambda pc, op: BLTZALL(pc, op.opcode, op.rs, op.imm16s),
    19: lambda pc, op: BGEZALL(pc, op.opcode, op.rs, op.imm16s),
}

def disassemble_regimm(pc, op):
    return regimm.get(op.regimm, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

tlb = {
    1: lambda pc, op: TLBR(pc, op.opcode),
    2: lambda pc, op: TLBWI(pc, op.opcode),
    6: lambda pc, op: TLBWR(pc, op.opcode),
    8: lambda pc, op: TLBP(pc, op.opcode),
    24: lambda pc, op: ERET(pc, op.opcode),
}

def disassemble_tlb(pc, op):
    return tlb.get(op.tlb, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop0 = {
    0: lambda pc, op: MFC0(pc, op.opcode, op.rt, op.rd),
    4: lambda pc, op: MTC0(pc, op.opcode, op.rd, op.rt),
    16: disassemble_tlb,
}

def disassemble_cop0(pc, op):
    return cop0.get(op.cop, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop1cond = {
    0: lambda pc, op: BC1F(pc, op.opcode, op.imm16s),
    1: lambda pc, op: BC1T(pc, op.opcode, op.imm16s),
    2: lambda pc, op: BC1FL(pc, op.opcode, op.imm16s),
    3: lambda pc, op: BC1TL(pc, op.opcode, op.imm16s),
}

def disassemble_cop1cond(pc, op):
    return cop1cond.get(op.c1cond, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop1s = {
    0: lambda pc, op: ADD_S(pc, op.opcode, op.fd, op.fs, op.ft),
    1: lambda pc, op: SUB_S(pc, op.opcode, op.fd, op.fs, op.ft),
    2: lambda pc, op: MUL_S(pc, op.opcode, op.fd, op.fs, op.ft),
    3: lambda pc, op: DIV_S(pc, op.opcode, op.fd, op.fs, op.ft),
    4: lambda pc, op: SQRT_S(pc, op.opcode, op.fd, op.fs),
    5: lambda pc, op: ABS_S(pc, op.opcode, op.fd, op.fs),
    6: lambda pc, op: MOV_S(pc, op.opcode, op.fd, op.fs),
    7: lambda pc, op: NEG_S(pc, op.opcode, op.fd, op.fs),
    8: lambda pc, op: ROUND_L_S(pc, op.opcode, op.fd, op.fs),
    9: lambda pc, op: TRUNC_L_S(pc, op.opcode, op.fd, op.fs),
    10: lambda pc, op: CEIL_L_S(pc, op.opcode, op.fd, op.fs),
    11: lambda pc, op: FLOOR_L_S(pc, op.opcode, op.fd, op.fs),
    12: lambda pc, op: ROUND_W_S(pc, op.opcode, op.fd, op.fs),
    13: lambda pc, op: TRUNC_W_S(pc, op.opcode, op.fd, op.fs),
    14: lambda pc, op: CEIL_W_S(pc, op.opcode, op.fd, op.fs),
    15: lambda pc, op: FLOOR_W_S(pc, op.opcode, op.fd, op.fs),
    33: lambda pc, op: CVT_D_S(pc, op.opcode, op.fd, op.fs),
    36: lambda pc, op: CVT_W_S(pc, op.opcode, op.fd, op.fs),
    37: lambda pc, op: CVT_L_S(pc, op.opcode, op.fd, op.fs),
    48: lambda pc, op: C_F_S(pc, op.opcode, op.fs, op.ft),
    49: lambda pc, op: C_UN_S(pc, op.opcode, op.fs, op.ft),
    50: lambda pc, op: C_EQ_S(pc, op.opcode, op.fs, op.ft),
    51: lambda pc, op: C_UEQ_S(pc, op.opcode, op.fs, op.ft),
    52: lambda pc, op: C_OLT_S(pc, op.opcode, op.fs, op.ft),
    53: lambda pc, op: C_ULT_S(pc, op.opcode, op.fs, op.ft),
    54: lambda pc, op: C_OLE_S(pc, op.opcode, op.fs, op.ft),
    55: lambda pc, op: C_ULE_S(pc, op.opcode, op.fs, op.ft),
    56: lambda pc, op: C_SF_S(pc, op.opcode, op.fs, op.ft),
    57: lambda pc, op: C_NGLE_S(pc, op.opcode, op.fs, op.ft),
    58: lambda pc, op: C_SEQ_S(pc, op.opcode, op.fs, op.ft),
    59: lambda pc, op: C_NGL_S(pc, op.opcode, op.fs, op.ft),
    60: lambda pc, op: C_LT_S(pc, op.opcode, op.fs, op.ft),
    61: lambda pc, op: C_NGE_S(pc, op.opcode, op.fs, op.ft),
    62: lambda pc, op: C_LE_S(pc, op.opcode, op.fs, op.ft),
    63: lambda pc, op: C_NGT_S(pc, op.opcode, op.fs, op.ft),
}

def disassemble_cop1s(pc, op):
    return cop1s.get(op.c1, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop1d = {
    0: lambda pc, op: ADD_D(pc, op.opcode, op.fd, op.fs, op.ft),
    1: lambda pc, op: SUB_D(pc, op.opcode, op.fd, op.fs, op.ft),
    2: lambda pc, op: MUL_D(pc, op.opcode, op.fd, op.fs, op.ft),
    3: lambda pc, op: DIV_D(pc, op.opcode, op.fd, op.fs, op.ft),
    4: lambda pc, op: SQRT_D(pc, op.opcode, op.fd, op.fs),
    5: lambda pc, op: ABS_D(pc, op.opcode, op.fd, op.fs),
    6: lambda pc, op: MOV_D(pc, op.opcode, op.fd, op.fs),
    7: lambda pc, op: NEG_D(pc, op.opcode, op.fd, op.fs),
    8: lambda pc, op: ROUND_L_D(pc, op.opcode, op.fd, op.fs),
    9: lambda pc, op: TRUNC_L_D(pc, op.opcode, op.fd, op.fs),
    10: lambda pc, op: CEIL_L_D(pc, op.opcode, op.fd, op.fs),
    11: lambda pc, op: FLOOR_L_D(pc, op.opcode, op.fd, op.fs),
    12: lambda pc, op: ROUND_W_D(pc, op.opcode, op.fd, op.fs),
    13: lambda pc, op: TRUNC_W_D(pc, op.opcode, op.fd, op.fs),
    14: lambda pc, op: CEIL_W_D(pc, op.opcode, op.fd, op.fs),
    15: lambda pc, op: FLOOR_W_D(pc, op.opcode, op.fd, op.fs),
    32: lambda pc, op: CVT_S_D(pc, op.opcode, op.fd, op.fs),
    36: lambda pc, op: CVT_W_D(pc, op.opcode, op.fd, op.fs),
    37: lambda pc, op: CVT_L_D(pc, op.opcode, op.fd, op.fs),
    48: lambda pc, op: C_F_D(pc, op.opcode, op.fs, op.ft),
    49: lambda pc, op: C_UN_D(pc, op.opcode, op.fs, op.ft),
    50: lambda pc, op: C_EQ_D(pc, op.opcode, op.fs, op.ft),
    51: lambda pc, op: C_UEQ_D(pc, op.opcode, op.fs, op.ft),
    52: lambda pc, op: C_OLT_D(pc, op.opcode, op.fs, op.ft),
    53: lambda pc, op: C_ULT_D(pc, op.opcode, op.fs, op.ft),
    54: lambda pc, op: C_OLE_D(pc, op.opcode, op.fs, op.ft),
    55: lambda pc, op: C_ULE_D(pc, op.opcode, op.fs, op.ft),
    56: lambda pc, op: C_SF_D(pc, op.opcode, op.fs, op.ft),
    57: lambda pc, op: C_NGLE_D(pc, op.opcode, op.fs, op.ft),
    58: lambda pc, op: C_SEQ_D(pc, op.opcode, op.fs, op.ft),
    59: lambda pc, op: C_NGL_D(pc, op.opcode, op.fs, op.ft),
    60: lambda pc, op: C_LT_D(pc, op.opcode, op.fs, op.ft),
    61: lambda pc, op: C_NGE_D(pc, op.opcode, op.fs, op.ft),
    62: lambda pc, op: C_LE_D(pc, op.opcode, op.fs, op.ft),
    63: lambda pc, op: C_NGT_D(pc, op.opcode, op.fs, op.ft),
}

def disassemble_cop1d(pc, op):
    return cop1d.get(op.c1, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop1w = {
    32: lambda pc, op: CVT_S_W(pc, op.opcode, op.fd, op.fs),
    33: lambda pc, op: CVT_D_W(pc, op.opcode, op.fd, op.fs),
}

def disassemble_cop1w(pc, op):
    return cop1w.get(op.c1, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop1l = {
    32: lambda pc, op: CVT_S_L(pc, op.opcode, op.fd, op.fs),
    33: lambda pc, op: CVT_D_L(pc, op.opcode, op.fd, op.fs),
}

def disassemble_cop1l(pc, op):
    return cop1l.get(op.c1, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

cop1 = {
    0: lambda pc, op: MFC1(pc, op.opcode, op.rt, op.fs),
    1: lambda pc, op: DMFC1(pc, op.opcode, op.rt, op.fs),
    2: lambda pc, op: CFC1(pc, op.opcode, op.rt, op.fs),
    4: lambda pc, op: MTC1(pc, op.opcode, op.fs, op.rt),
    5: lambda pc, op: DMTC1(pc, op.opcode, op.fs, op.rt),
    6: lambda pc, op: CTC1(pc, op.opcode, op.fs, op.rt),
    8: disassemble_cop1cond,
    16: disassemble_cop1s,
    17: disassemble_cop1d,
    20: disassemble_cop1w,
    21: disassemble_cop1l,
}

def disassemble_cop1(pc, op):
    return cop1.get(op.cop, lambda pc, op: Unknown(pc, op.opcode))(pc, op)

major = {
    0: disassemble_special,
    1: disassemble_regimm,
    2: lambda pc, op: J(pc, op.opcode, op.imm26),
    3: lambda pc, op: JAL(pc, op.opcode, op.imm26),
    4: lambda pc, op: BEQ(pc, op.opcode, op.rs, op.rt, op.imm16s),
    5: lambda pc, op: BNE(pc, op.opcode, op.rs, op.rt, op.imm16s),
    6: lambda pc, op: BLEZ(pc, op.opcode, op.rs, op.imm16s),
    7: lambda pc, op: BGTZ(pc, op.opcode, op.rs, op.imm16s),
    8: lambda pc, op: ADDI(pc, op.opcode, op.rt, op.rs, op.imm16s),
    9: lambda pc, op: ADDIU(pc, op.opcode, op.rt, op.rs, op.imm16s),
    10: lambda pc, op: SLTI(pc, op.opcode, op.rt, op.rs, op.imm16s),
    11: lambda pc, op: SLTIU(pc, op.opcode, op.rt, op.rs, op.imm16s),
    12: lambda pc, op: ANDI(pc, op.opcode, op.rt, op.rs, op.imm16u),
    13: lambda pc, op: ORI(pc, op.opcode, op.rt, op.rs, op.imm16u),
    14: lambda pc, op: XORI(pc, op.opcode, op.rt, op.rs, op.imm16u),
    15: lambda pc, op: LUI(pc, op.opcode, op.rt, op.imm16s),
    16: disassemble_cop0,
    17: disassemble_cop1,
    20: lambda pc, op: BEQL(pc, op.opcode, op.rs, op.rt, op.imm16s),
    21: lambda pc, op: BNEL(pc, op.opcode, op.rs, op.rt, op.imm16s),
    22: lambda pc, op: BLEZL(pc, op.opcode, op.rs, op.imm16s),
    23: lambda pc, op: BGTZL(pc, op.opcode, op.rs, op.imm16s),
    24: lambda pc, op: DADDI(pc, op.opcode, op.rt, op.rs, op.imm16s),
    25: lambda pc, op: DADDIU(pc, op.opcode, op.rt, op.rs, op.imm16s),
    26: lambda pc, op: LDL(pc, op.opcode, op.rt, op.rs, op.imm16s),
    27: lambda pc, op: LDR(pc, op.opcode, op.rt, op.rs, op.imm16s),
    32: lambda pc, op: LB(pc, op.opcode, op.rt, op.rs, op.imm16s),
    33: lambda pc, op: LH(pc, op.opcode, op.rt, op.rs, op.imm16s),
    34: lambda pc, op: LWL(pc, op.opcode, op.rt, op.rs, op.imm16s),
    35: lambda pc, op: LW(pc, op.opcode, op.rt, op.rs, op.imm16s),
    36: lambda pc, op: LBU(pc, op.opcode, op.rt, op.rs, op.imm16s),
    37: lambda pc, op: LHU(pc, op.opcode, op.rt, op.rs, op.imm16s),
    38: lambda pc, op: LWR(pc, op.opcode, op.rt, op.rs, op.imm16s),
    39: lambda pc, op: LWU(pc, op.opcode, op.rt, op.rs, op.imm16s),
    40: lambda pc, op: SB(pc, op.opcode, op.rt, op.rs, op.imm16s),
    41: lambda pc, op: SH(pc, op.opcode, op.rt, op.rs, op.imm16s),
    42: lambda pc, op: SWL(pc, op.opcode, op.rt, op.rs, op.imm16s),
    43: lambda pc, op: SW(pc, op.opcode, op.rt, op.rs, op.imm16s),
    44: lambda pc, op: SDL(pc, op.opcode, op.rt, op.rs, op.imm16s),
    45: lambda pc, op: SDR(pc, op.opcode, op.rt, op.rs, op.imm16s),
    46: lambda pc, op: SWR(pc, op.opcode, op.rt, op.rs, op.imm16s),
    47: lambda pc, op: CACHE(pc, op.opcode, op.rt, op.rs, op.imm16s),
    48: lambda pc, op: LL(pc, op.opcode, op.rt, op.rs, op.imm16s),
    49: lambda pc, op: LWC1(pc, op.opcode, op.ft, op.rs, op.imm16s),
    53: lambda pc, op: LDC1(pc, op.opcode, op.ft, op.rs, op.imm16s),
    55: lambda pc, op: LD(pc, op.opcode, op.rt, op.rs, op.imm16s),
    56: lambda pc, op: SC(pc, op.opcode, op.rt, op.rs, op.imm16s),
    57: lambda pc, op: SWC1(pc, op.opcode, op.ft, op.rs, op.imm16s),
    61: lambda pc, op: SDC1(pc, op.opcode, op.ft, op.rs, op.imm16s),
    63: lambda pc, op: SD(pc, op.opcode, op.rt, op.rs, op.imm16s),
}

def disassemble(pc, opcode):
    op = OpcodeParser(opcode)
    return major.get(op.major, lambda pc, op: Unknown(pc, op.opcode))(pc, op)
