# GDB Extensions for Lua 5.3
# Author: chu <1871361697@qq.com>
# Github: http://github.com/9chu
# Inspired by https://github.com/xjdrew/lua-gdb
#
# Commands:
#   - glua_traceback [L]
#   - glua_stackinfo [L [idx]]
#   - glua_objectinfo [L]
#   - glua_break [L] filename line_number
#   - glua_breakr [L] regex line_number
#
# Utility functions:
#   - $lua_getglobalstate(lua_State L) -> global_State*
#   - $lua_nilobject() -> TValue
#   - $lua_index2value(lua_State L, int idx) -> TValue*
#   - $lua_rawget(TValue* table|Table* table, TValue key) -> TValue*
#   - $lua_rawgeti(TValue* table|Table* table, int idx) -> TValue*
#   - $lua_rawgets(TValue* table|Table* table, string key) -> TValue*
#   - $lua_rawlen(TValue* v|Table* v) -> int
#   - $lua_getcachedstring(lua_State L, string key) -> TString*
#   - $lua_getregistrytable(lua_State L) -> TValue*
#   - $lua_getglobaltable(lua_State L) -> TValue*
#   - $lua_getstack(lua_State L, int idx) -> CallInfo*
#   - $lua_getlocal(lua_State L, int frame, int idx) -> TValue*
#   - $lua_getlocalname(lua_State L, int frame, int idx) -> string
#   - $lua_getmetatable(TValue* v) -> Table*
#
# Pretty printers for:
#   - TValue
#   - TString
#   - Table
#   - CClosure
#   - LClosure
#   - Udata
#   - Proto
#
# Hint:
#   - using gdb command 'set print pretty on' to format the output more readable
#   - using gdb command 'set python print-stack full' to debug this script
#

from __future__ import print_function  # for py2

import os
import re
import sys
import math

print("GDB Lua5.3 Extension", file=sys.stderr)
print("* To use this extension, you have to compile lua with debug symbols.", file=sys.stderr)
print("* Please see the document for more details.", file=sys.stderr)

if sys.version > '3':
    xrange = range
    long = int

# Basic wrappers


LUA_TNONE = -1
LUA_TNIL = 0
LUA_TBOOLEAN = 1
LUA_TLIGHTUSERDATA = 2
LUA_TNUMBER = 3
LUA_TSTRING = 4
LUA_TTABLE = 5
LUA_TFUNCTION = 6
LUA_TUSERDATA = 7
LUA_TTHREAD = 8

LUA_NUMTAGS = 9
LUA_TPROTO = LUA_NUMTAGS  # Function prototypes
LUA_TDEADKEY = (LUA_NUMTAGS + 1)  # Removed keys in tables

LUA_TLCL = (LUA_TFUNCTION | (0 << 4))  # Lua closure
LUA_TLCF = (LUA_TFUNCTION | (1 << 4))  # Light C function
LUA_TCCL = (LUA_TFUNCTION | (2 << 4))  # C closure

LUA_TSHRSTR = (LUA_TSTRING | (0 << 4))  # Short strings
LUA_TLNGSTR = (LUA_TSTRING | (1 << 4))  # Long strings

LUA_TNUMFLT = (LUA_TNUMBER | (0 << 4))  # Float numbers
LUA_TNUMINT = (LUA_TNUMBER | (1 << 4))  # Integer numbers

BIT_ISCOLLECTABLE = (1 << 6)  # Collectable objects

CIST_OAH = 1 << 0  # Original value of 'allowhook'
CIST_LUA = 1 << 1  # Call is running a Lua function
CIST_HOOKED = 1 << 2  # Call is running a debug hook
CIST_FRESH = 1 << 3  # Call is running on a fresh invocation of luaV_execute
CIST_YPCALL = 1 << 4  # Call is a yieldable protected call
CIST_TAIL = 1 << 5  # Call was tail called
CIST_HOOKYIELD = 1 << 6  # Last hook called yielded
CIST_LEQ = 1 << 7  # Using __lt for __le
CIST_FIN = 1 << 8  # Call is running a finalizer


def pointer_of(v):
    t = v.type.pointer()
    return gdb.Value(v.address).cast(t)


class TValueWrapper:
    def __init__(self, value):
        self.value = value

    def get_raw_type_tag(self):  # rttype
        return self.value["tt_"]

    def get_type_tag(self):  # ttype
        return self.get_raw_type_tag() & 0x3F

    def get_type_tag_no_variants(self):  # ttnov
        return self.get_raw_type_tag() & 0x0F

    def check_tag(self, t):  # checktag
        return self.get_raw_type_tag() == t

    def check_type(self, t):  # checktype
        return self.get_type_tag_no_variants() == t

    def is_number(self):
        return self.check_type(LUA_TNUMBER)

    def is_float(self):
        return self.check_tag(LUA_TNUMFLT)

    def is_integer(self):
        return self.check_tag(LUA_TNUMINT)

    def is_nil(self):
        return self.check_tag(LUA_TNIL)

    def is_boolean(self):
        return self.check_tag(LUA_TBOOLEAN)

    def is_light_userdata(self):
        return self.check_tag(LUA_TLIGHTUSERDATA)

    def is_string(self):
        return self.check_type(LUA_TSTRING)

    def is_short_string(self):
        return self.check_tag(LUA_TSHRSTR | BIT_ISCOLLECTABLE)

    def is_long_string(self):
        return self.check_tag(LUA_TLNGSTR | BIT_ISCOLLECTABLE)

    def is_table(self):
        return self.check_tag(LUA_TTABLE | BIT_ISCOLLECTABLE)

    def is_function(self):
        return self.check_type(LUA_TFUNCTION)

    def is_closure(self):  # ttisclosure
        return (self.get_raw_type_tag() & 0x1F) == LUA_TFUNCTION

    def is_c_closure(self):  # ttisCclosure
        return self.check_tag(LUA_TCCL | BIT_ISCOLLECTABLE)

    def is_lua_closure(self):  # ttisLclosure
        return self.check_tag(LUA_TLCL | BIT_ISCOLLECTABLE)

    def is_light_c_function(self):  # ttislcf
        return self.check_tag(LUA_TLCF)

    def is_full_userdata(self):
        return self.check_tag(LUA_TUSERDATA | BIT_ISCOLLECTABLE)

    def is_thread(self):
        return self.check_tag(LUA_TTHREAD | BIT_ISCOLLECTABLE)

    def is_prototype(self):
        return self.check_tag(LUA_TPROTO)

    def is_dead_key(self):
        return self.check_tag(LUA_TDEADKEY)

    def is_collectable(self):
        return (self.get_raw_type_tag() & BIT_ISCOLLECTABLE) != 0

    def get_value(self):  # val_
        return self.value["value_"]

    def get_integer(self):  # ivalue
        assert self.is_integer()
        return self.get_value()["i"]

    def get_float(self):  # fltvalue
        assert self.is_float()
        return self.get_value()["n"]

    def get_number(self):  # nvalue
        if self.is_integer():
            return long(self.get_integer())
        return float(self.get_float())

    def get_light_userdata(self):  # pvalue
        assert self.is_light_userdata()
        return self.get_value()["p"]

    def get_light_c_function(self):  # fvalue
        assert self.is_light_c_function()
        return self.get_value()["f"]

    def get_boolean(self):  # bvalue
        assert self.is_boolean()
        if self.get_value()["b"] == 0:
            return False
        return True

    def get_gc_value(self):  # gcvalue
        assert self.is_collectable()
        return self.get_value()["gc"]

    def get_gc_union(self):  # cast_u
        assert self.is_collectable()
        t = gdb.lookup_type("union GCUnion").pointer()
        return self.get_gc_value().cast(t)

    def get_tstring_value(self):  # tsvalue
        assert self.is_string()
        return pointer_of(self.get_gc_union()["ts"])

    def get_userdata_value(self):  # uvalue
        assert self.is_full_userdata()
        return pointer_of(self.get_gc_union()["u"])

    def get_closure_value(self):  # clvalue
        assert self.is_closure()
        return pointer_of(self.get_gc_union()["cl"])

    def get_lua_closure_value(self):  # clLvalue
        assert self.is_lua_closure()
        return pointer_of(self.get_closure_value()["l"])

    def get_c_closure_value(self):  # clCvalue
        assert self.is_c_closure()
        return pointer_of(self.get_closure_value()["c"])

    def get_table_value(self):  # hvalue
        assert self.is_table()
        return pointer_of(self.get_gc_union()["h"])

    def get_thread_value(self):  # thvalue
        assert self.is_thread()
        return pointer_of(self.get_gc_union()["th"])

    def get_prototype_value(self):  # gco2p
        assert self.is_prototype()
        return pointer_of(self.get_gc_union()["p"])

    def get_dead_key_value(self):  # deadvalue
        assert self.is_dead_key()
        return self.get_gc_value()

    def is_false(self):  # l_isfalse
        return self.is_nil() or (self.is_boolean() and (not self.get_boolean()))


class TStringWrapper:
    def __init__(self, value):
        self.value = value

    def get_length(self):
        if self.value["tt"] == LUA_TSHRSTR:
            return self.value["shrlen"]
        return self.value["u"]["lnglen"]

    def get_buffer(self):
        t = gdb.lookup_type("char").pointer()
        sz = gdb.lookup_type("TString").sizeof
        return gdb.Value(long(self.value.address) + sz).cast(t)

    def to_string(self):
        return self.get_buffer().string()

    def equals_to(self, s):
        s = s.encode("utf-8")
        l = self.get_length()
        buf = self.get_buffer()
        if l != len(s):
            return False
        for i in range(0, l):
            if (int(buf[i]) & 0xFF) != ord(s[i]):
                return False
        return True


class UDataWrapper:  # TODO: Support reading uservalue field
    def __init__(self, value):
        self.value = value

    def get_length(self):
        return self.value["len"]

    def get_buffer(self):
        t = gdb.lookup_type("void").pointer()
        sz = gdb.lookup_type("Udata").sizeof
        return gdb.Value(long(self.value.address) + sz).cast(t)

    def get_metatable(self):
        return self.value["metatable"]


class CClosureWrapper:
    def __init__(self, value):
        self.value = value

    def get_function(self):
        return self.value["f"]

    def get_upvalue_count(self):
        return self.value["nupvalues"]

    def get_upvalue(self, i):
        return self.value["upvalue"][i]


class LClosureWrapper:
    def __init__(self, value):
        self.value = value

    def get_prototype(self):
        return self.value["p"]

    def get_upvalue_count(self):
        return self.value["nupvalues"]

    def get_upvalue(self, i):
        return self.value["upvals"][i]["v"].dereference()


class TableWrapper:
    def __init__(self, value):
        self.value = value

    def __iter__(self):
        # array part
        i = 0
        sz = self.value["sizearray"]
        while i < sz:
            v = self.value["array"] + i
            i += 1
            yield i, v

        # hash part
        j = 0
        last = 1 << self.value["lsizenode"]
        while j < last:
            node = self.value["node"] + j
            j += 1
            k = node["i_key"]["tvk"]
            v = node["i_val"]
            if TValueWrapper(k).is_nil():
                continue
            yield k, pointer_of(v)

    def get_metatable(self):
        return self.value["metatable"]


class ProtoWrapper:
    def __init__(self, value):
        self.value = value

    def get_arg_count(self):
        return self.value["numparams"]

    def is_vararg(self):
        return self.value["is_vararg"] != 0

    def get_upvalue_count(self):
        return self.value["sizeupvalues"]

    def get_local_value_count(self):
        return self.value["sizelocvars"]

    def get_source(self):
        return self.value["source"]

    def get_line_defined(self):
        return self.value["linedefined"]

    def local_values(self):
        for i in range(0, self.get_local_value_count()):
            yield i, self.value["locvars"][i]

    def upvalues(self):
        for i in range(0, self.get_upvalue_count()):
            yield i, self.value["upvalues"][i]


class CallInfoWrapper:
    def __init__(self, value):
        self.value = value

    def is_lua(self):
        return (self.value["callstatus"] & CIST_LUA) != 0

    def is_tailcall(self):
        return (self.value["callstatus"] & CIST_TAIL) != 0

    def is_finalizer(self):
        return (self.value["callstatus"] & CIST_FIN) != 0

    def is_hooked(self):
        return (self.value["callstatus"] & CIST_HOOKED) != 0

    def get_lua_base(self):
        assert self.is_lua()
        return self.value["u"]["l"]["base"]

    def get_base(self):
        assert not self.is_lua()
        return self.value["func"] + 1

    def get_next(self):
        return CallInfoWrapper(self.value["next"].dereference())

    def get_prev(self):
        return CallInfoWrapper(self.value["previous"].dereference())

    def get_func(self):
        return self.value["func"]

    def get_current_pc(self):
        assert self.is_lua()
        pc = self.value["u"]["l"]["savedpc"]
        p = TValueWrapper(self.get_func().dereference()).get_lua_closure_value()["p"]
        return long(pc - p["code"] - 1)

    def get_current_line(self):
        assert self.is_lua()
        pc = self.value["u"]["l"]["savedpc"]
        p = TValueWrapper(self.get_func().dereference()).get_lua_closure_value()["p"]
        pci = long(pc - p["code"] - 1)
        return p["lineinfo"][pci] if p["lineinfo"] else -1


# Lua Function Implement


LUAI_MAXSTACK = 15000
LUA_REGISTRYINDEX = -LUAI_MAXSTACK - 1000
LUA_MAXUPVAL = 255

LUAI_HASHLIMIT = 5

LUA_RIDX_MAINTHREAD = 1
LUA_RIDX_GLOBALS = 2
LUA_RIDX_LAST = LUA_RIDX_GLOBALS

LUAI_MAXSHORTLEN = 40
STRCACHE_N = 53
STRCACHE_M = 2

LUA_IDSIZE = 60

TM_INDEX = 0
TM_NEWINDEX = 1
TM_GC = 2
TM_MODE = 3
TM_LEN = 4
TM_EQ = 5
TM_ADD = 6
TM_SUB = 7
TM_MUL = 8
TM_MOD = 9
TM_POW = 10
TM_DIV = 11
TM_IDIV = 12
TM_BAND = 13
TM_BOR = 14
TM_BXOR = 15
TM_SHL = 16
TM_SHR = 17
TM_UNM = 18
TM_BNOT = 19
TM_LT = 20
TM_LE = 21
TM_CONCAT = 22
TM_CALL = 23
TM_N = 24

OP_MOVE = 0
OP_LOADK = 1
OP_LOADKX = 2
OP_LOADBOOL = 3
OP_LOADNIL = 4
OP_GETUPVAL = 5
OP_GETTABUP = 6
OP_GETTABLE = 7
OP_SETTABUP = 8
OP_SETUPVAL = 9
OP_SETTABLE = 10
OP_NEWTABLE = 11
OP_SELF = 12
OP_ADD = 13
OP_SUB = 14
OP_MUL = 15
OP_MOD = 16
OP_POW = 17
OP_DIV = 18
OP_IDIV = 19
OP_BAND = 20
OP_BOR = 21
OP_BXOR = 22
OP_SHL = 23
OP_SHR = 24
OP_UNM = 25
OP_BNOT = 26
OP_NOT = 27
OP_LEN = 28
OP_CONCAT = 29
OP_JMP = 30
OP_EQ = 31
OP_LT = 32
OP_LE = 33
OP_TEST = 34
OP_TESTSET = 35
OP_CALL = 36
OP_TAILCALL = 37
OP_RETURN = 38
OP_FORLOOP = 39
OP_FORPREP = 40
OP_TFORCALL = 41
OP_TFORLOOP = 42
OP_SETLIST = 43
OP_CLOSURE = 44
OP_VARARG = 45
OP_EXTRAARG = 46

OP_MASK_ARG_N = 0
OP_MASK_ARG_U = 1
OP_MASK_ARG_R = 2
OP_MASK_ARG_K = 3

OP_MODE_iABC = 0
OP_MODE_iABx = 1
OP_MODE_iAsBx = 2
OP_MODE_iAx = 3

SIZE_C = 9
SIZE_B = 9
SIZE_Bx = (SIZE_C + SIZE_B)
SIZE_A = 8
SIZE_Ax = (SIZE_C + SIZE_B + SIZE_A)

SIZE_OP = 6

POS_OP = 0
POS_A = (POS_OP + SIZE_OP)
POS_C = (POS_A + SIZE_A)
POS_B = (POS_C + SIZE_C)
POS_Bx = POS_C
POS_Ax = POS_A
MAXARG_sBx = 2147483647  # INT_MAX

luaP_opmodes = [
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABx),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_N << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABx),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_R << 2) | OP_MODE_iABC),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iAsBx),
    ((1 << 7) | (0 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((1 << 7) | (0 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((1 << 7) | (0 << 6) | (OP_MASK_ARG_K << 4) | (OP_MASK_ARG_K << 2) | OP_MODE_iABC),
    ((1 << 7) | (0 << 6) | (OP_MASK_ARG_N << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((1 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iAsBx),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iAsBx),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_N << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_R << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iAsBx),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iABC),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABx),
    ((0 << 7) | (1 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_N << 2) | OP_MODE_iABC),
    ((0 << 7) | (0 << 6) | (OP_MASK_ARG_U << 4) | (OP_MASK_ARG_U << 2) | OP_MODE_iAx),
]


def lua_op_mask1(n, p):
    return (~((~0) << n)) << p


def lua_op_getcode(i):
    return (i >> POS_OP) & lua_op_mask1(SIZE_OP, 0)


def lua_op_getarg(i, pos, size):
    return (i >> pos) & lua_op_mask1(size, 0)


def lua_op_getarga(i):
    return lua_op_getarg(i, POS_A, SIZE_A)


def lua_op_getargb(i):
    return lua_op_getarg(i, POS_B, SIZE_B)


def lua_op_getargc(i):
    return lua_op_getarg(i, POS_C, SIZE_C)


def lua_op_getargax(i):
    return lua_op_getarg(i, POS_Ax, SIZE_Ax)


def lua_op_getargbx(i):
    return lua_op_getarg(i, POS_Bx, SIZE_Bx)


def lua_op_getargsbx(i):
    return lua_op_getargbx(i) - MAXARG_sBx


def lua_op_testamode(m):
    return (luaP_opmodes[m] & (1 << 6)) != 0


class LuaDebugInfo:
    def __init__(self):
        self.event = 0
        self.name = ""  # (n)
        self.namewhat = ""  # (n) "global", "local", "field", "method"
        self.what = ""  # (S) "Lua", "C", "main", "tail"
        self.source = ""  # (S)
        self.currentline = -1  # (l)
        self.linedefined = -1  # (S)
        self.lastlinedefined = -1  # (S)
        self.nups = 0  # (u) number of upvalues
        self.nparams = 0  # (u) number of parameters
        self.isvararg = False  # (u)
        self.istailcall = False  # (t)
        self.short_src = ""  # (S)
        self.address = None

    def __str__(self):
        if self.what == "main":
            name = "[Main chunk]"
        elif self.what == "C":
            name = str(self.address)
        else:
            name = self.name

        if self.currentline >= 0:
            currentline = ":%d" % self.currentline
        else:
            currentline = ""

        if  self.istailcall:
            tailcall = " (tailcall)"
        else:
            tailcall = ""

        if len( self.short_src) == 0:
            source = "?"
        else:
            source =  self.short_src

        if  self.linedefined >= 0:
            linedefined = ":%d" %  self.linedefined
        else:
            linedefined = ""
        return "%s%s%s @ %s%s" % (name, currentline, tailcall, source, linedefined)


def lua_ispseudo(idx):
    return idx <= LUA_REGISTRYINDEX


def lua_getglobalstate(L):
    return L["l_G"]


def lua_nilobject():
    ret = gdb.lookup_symbol("luaO_nilobject_")
    if ret[0] is not None:
        t = gdb.lookup_type("TValue")
        return ret[0].value().cast(t)
    return None


def lua_index2value(L, idx):
    ci = L["ci"]
    if idx > 0:
        o = ci["func"] + idx
        assert idx <= ci["top"] - (ci["func"] + 1), "invalid stack index"
        if o >= L["top"]:
            return None
        return o
    elif not lua_ispseudo(idx):
        assert idx != 0 and -idx <= L["top"] - (ci["func"] + 1), "invalid stack index"
        return L["top"] + idx
    elif idx == LUA_REGISTRYINDEX:
        return lua_getglobalstate(L)["l_registry"]
    else:
        idx = LUA_REGISTRYINDEX - idx
        assert idx <= LUA_MAXUPVAL + 1, "upvalue index out of range"
        v = TValueWrapper((ci["func"]).dereference())
        if v.is_light_c_function():
            return None
        func = v.get_c_closure_value()
        if idx <= func["nupvalues"]:
            return func["upvalue"][idx - 1]
        return None


def lua_hashfloat(n):
    n = float(n)
    n, i = math.frexp(n)
    n *= -float(-2147483648)
    if not (float(-2147483648) <= n < -float(-2147483648)):
        return 0
    ni = int(n)
    u = long(abs(i)) + long(abs(ni))
    return u if u <= 2147483647 else ~u


def lua_hashstring(str, l, seed):
    h = seed ^ l
    step = (l >> LUAI_HASHLIMIT) + 1
    i = l
    while i >= step:
        h ^= ((h << 5) + (h >> 2) + (int(str[i - 1]) & 0xFF))
        i -= step
    return h


def lua_hashlongstr(ts):
    assert ts["tt"] == LUA_TLNGSTR, "bad argument"
    if ts["extra"] == 0:
        lua_hashstring(TStringWrapper(ts).get_buffer(), ts["u"]["lnglen"], ts["hash"])
    return ts["hash"]


def lua_rawequalobj(obj1, obj2):
    t1 = TValueWrapper(obj1)
    t2 = TValueWrapper(obj2)
    if t1.get_type_tag() != t2.get_type_tag():
        if t1.get_type_tag_no_variants() != t2.get_type_tag_no_variants() or t1.get_type_tag_no_variants() != LUA_TNUMBER:
            return False
        else:
            tn1 = t1.get_number()
            tn2 = t2.get_number()
            return math.floor(tn1) == tn1 and math.floor(tn2) == tn2 and long(tn1) == long(tn2)
    if t1.is_nil():
        return True
    elif t1.is_integer():
        return t1.get_integer() == t2.get_integer()
    elif t1.is_float():
        return t1.get_float() == t2.get_float()
    elif t1.is_boolean():
        return t1.get_boolean() == t2.get_boolean()
    elif t1.is_light_userdata():
        return t1.get_light_userdata() == t2.get_light_userdata()
    elif t1.is_light_c_function():
        return t1.get_light_c_function() == t2.get_light_c_function()
    elif t1.is_long_string():
        if t1.get_tstring_value() == t2.get_tstring_value():
            return True
        ts1 = TStringWrapper(t1)
        ts2 = TStringWrapper(t2)
        if ts1.get_length() != ts2.get_length():
            return False
        buf1 = ts1.get_buffer()
        buf2 = ts2.get_buffer()
        for i in range(0, ts1.get_length()):
            if buf1[i] != buf2[i]:
                return False
        return True
    else:
        return t1.get_gc_value().address == t2.get_gc_value().address


def lua_rawget(t, key):
    if t.type.unqualified().target().tag != "Table":
        t = TValueWrapper(t)
        assert t.is_table(), "arg1 must be a table"
        t = t.get_table_value()
    k = TValueWrapper(key)

    nsz = 1 << t["lsizenode"]
    assert nsz & (nsz - 1) == 0, "invalid table data"

    # fast way
    if k.is_short_string():
        ts = k.get_tstring_value()
        assert ts["tt"] == LUA_TSHRSTR, "invalid key data"
        n = t["node"][ts["hash"] & (nsz - 1)].address
        while True:
            gkey = TValueWrapper(n["i_key"]["tvk"])
            if gkey.is_short_string() and gkey.get_tstring_value().address == ts.address:
                return n["i_val"]
            else:
                nx = n["i_key"]["nk"]["next"]
                if nx == 0:
                    break
                n += nx
        return lua_nilobject()
    elif k.is_integer():
        return lua_rawgeti(t, k.get_integer())
    elif k.is_nil():
        return lua_nilobject()
    elif k.is_float():
        f = float(k.get_float())
        if math.floor(f) == f:
            return lua_rawgeti(t, long(f))
        # fall through

    # generic way
    if k.is_integer():
        n = t["node"][k.get_integer() & (nsz - 1)]
    elif k.is_float():
        n = t["node"][lua_hashfloat(k.get_float()) % ((nsz - 1) | 1)]
    elif k.is_short_string():
        ts = k.get_tstring_value()
        assert ts["tt"] == LUA_TSHRSTR, "invalid key data"
        n = t["node"][ts["hash"] & (nsz - 1)]
    elif k.is_long_string():
        ts = k.get_tstring_value()
        n = t["node"][lua_hashlongstr(ts.dereference()) & (nsz - 1)]
    elif k.is_boolean():
        n = t["node"][int(k.get_boolean()) & (nsz - 1)]
    elif k.is_light_userdata():
        n = t["node"][(long(k.get_light_userdata()) & 4294967295) % ((nsz - 1) | 1)]
    elif k.is_light_c_function():
        n = t["node"][(long(k.get_light_c_function()) & 4294967295) % ((nsz - 1) | 1)]
    else:
        assert not k.is_dead_key(), "cannot index deadkey"
        n = t["node"][(long(k.get_gc_value().address) & 4294967295) % ((nsz - 1) | 1)]
    n = n.address
    while True:
        if lua_rawequalobj(n["i_key"]["tvk"], key):
            return n["i_val"]
        else:
            nx = n["i_key"]["nk"]["next"]
            if nx == 0:
                break
            n += nx
    return lua_nilobject()


def lua_rawgets(t, key):
    if t.type.unqualified().target().tag != "Table":
        t = TValueWrapper(t)
        assert t.is_table(), "arg1 must be a table"
        t = t.get_table_value()
    s = key.string()

    # cause we don know anything about the lua state, the only way is to visit all the nodes
    # so this method is really slow
    j = 0
    last = 1 << t["lsizenode"]
    while j < last:
        node = t["node"] + j
        j += 1
        k = TValueWrapper(node["i_key"]["tvk"])
        v = node["i_val"]
        if k.is_string():
            ts = TStringWrapper(k.get_tstring_value().dereference())
            if ts.equals_to(s):
                return v
    return lua_nilobject()


def lua_rawgeti(t, idx):
    if t.type.unqualified().target().tag != "Table":
        t = TValueWrapper(t)
        assert t.is_table(), "arg1 must be a table"
        t = t.get_table_value()
    if 0 <= idx - 1 < t["sizearray"]:
        return t["array"][idx - 1]
    else:
        nsz = 1 << t["lsizenode"]
        assert nsz & (nsz - 1) == 0, "invalid table data"
        n = t["node"][idx & (nsz - 1)].address
        while True:
            gkey = TValueWrapper(n["i_key"]["tvk"])
            if gkey.is_integer() and gkey.get_integer() == idx:
                return n["i_val"]
            else:
                nx = n["i_key"]["nk"]["next"]
                if nx == 0:
                    break
                n += nx
        return lua_nilobject()


def lua_getcachedstring(L, str):
    s = str.string().encode("utf-8")
    g = lua_getglobalstate(L)
    for i in range(0, STRCACHE_N):
        p = g["strcache"][i]
        for j in range(0, STRCACHE_M):
            ts = TStringWrapper(p[j])
            if ts.equals_to(s):
                return p[j]
    if len(s) <= LUAI_MAXSHORTLEN:
        h = lua_hashstring(str, len(s), g["seed"])
        list = g["strt"]["hash"][h & (g["strt"]["size"] - 1)]
        pts = list
        while pts != 0:
            ts = TStringWrapper(pts.dereference())
            if ts.equals_to(s):
                return pts  # FIXME: this object may be in GC
            pts = pts["u"]["hnext"]
    return None


def lua_getregistrytable(L):
    return lua_index2value(L, LUA_REGISTRYINDEX)


def lua_getglobaltable(L):
    return lua_rawgeti(lua_getregistrytable(L), LUA_RIDX_GLOBALS)


def lua_getstack(L, level):
    assert level >= 0, "invalid (negative) level"
    ci = L["ci"]
    while level > 0 and ci != L["base_ci"].address:
        level -= 1
        ci = ci["previous"]
    if level == 0 and ci != L["base_ci"].address:  # level found?
        return ci
    raise RuntimeError("CallInfo not found")


def lua_getlocalname(f, local_number, pc):
    i = 0
    while i < f["sizelocvars"] and f["locvars"][i]["startpc"] <= pc:
        if pc < f["locvars"][i]["endpc"]:  # is variable active?
            local_number -= 1
            if local_number == 0:
                return TStringWrapper(f["locvars"][i]["varname"].dereference()).to_string()
        i += 1
    return None


def lua_getlocal(L, callinfo, n):
    # luastack:
    #   local
    #   arg2
    #   arg1             <- base
    #   vararg2
    #   vararg1
    #   nil              <- for fix arg2
    #   nil              <- for fix arg1
    #   callee           <- ci->func
    ci = CallInfoWrapper(callinfo)
    name = None
    if ci.is_lua():
        if n < 0:  # vararg values
            f = TValueWrapper(ci.get_func().dereference()).get_lua_closure_value()["p"]
            nparams = f["numparams"]
            n = -n
            if n >= long(ci.get_lua_base() - ci.get_func()) - nparams:
                return None  # no such vararg
            else:
                name = "(*vararg)"
                return name, ci.get_func() + nparams + n
        else:
            base = ci.get_lua_base()
            name = lua_getlocalname(TValueWrapper(ci.get_func().dereference()).get_lua_closure_value()["p"], n, ci.get_current_pc())
    else:
        base = ci.get_base()
    if name is None:  # no 'standard' name
        limit = L["top"] if callinfo.address == L["ci"] else ci.get_next().get_func()
        if limit - base >= n > 0:  # is 'n' inside 'ci' stack
            name = "(*temporary)"  # generic name for any valid slot
        else:
            return None
    return name, base + (n - 1)


def lua_chunkid(source, bufflen):
    l = len(source)
    if source[0] == '=':
        if l <= bufflen:
            return source[1:]
        else:
            return source[1:bufflen]
    elif source[0] == '@':
        if l <= bufflen:
            return source[1:]
        else:
            return "..." + source[1 + l - bufflen:1 + l]
    else:
        nl = source.find('\n')
        bufflen -= 15
        if l < bufflen and nl < 0:
            return "[string \"" + source + "\"]"
        else:
            if nl >= 0:
                l = nl
            if l > bufflen:
                l = bufflen
            return "[string \"" + source[0:l] + "...\"]"


def lua_filterpc(pc, jmptarget):
    if pc < jmptarget:
        return -1
    return pc


def lua_findsetreg(p, lastpc, reg):
    setreg = -1
    jmptarget = 0
    for pc in range(0, lastpc):
        i = int(p["code"][pc])
        op = lua_op_getcode(i)
        a = lua_op_getarga(i)
        if op == OP_LOADNIL:
            b = lua_op_getargb(i)
            if a <= reg <= a + b:
                setreg = lua_filterpc(pc, jmptarget)
        elif op == OP_TFORCALL:
            if reg >= a + 2:
                setreg = lua_filterpc(pc, jmptarget)
        elif op == OP_CALL or op == OP_TAILCALL:
            if reg >= a:
                setreg = lua_filterpc(pc, jmptarget)
        elif op == OP_JMP:
            b = lua_op_getargsbx(i)
            dest = pc + 1 + b
            if pc < dest <= lastpc:
                if dest > jmptarget:
                    jmptarget = dest
        else:
            if lua_op_testamode(op) and reg == a:
                setreg = lua_filterpc(pc, jmptarget)
    return setreg


def lua_upvalname(p, uv):
    assert uv < p["sizeupvalues"]
    s = p["upvalues"][uv]["name"]
    if s:
        return TStringWrapper(s.dereference()).to_string()
    return "?"


def lua_kname(p, pc, c):
    if (c & (1 << (SIZE_B - 1))) != 0:
        kvalue = p["k"][c & (~(1 << (SIZE_B - 1)))]
        kw = TValueWrapper(kvalue)
        if kw.is_string():
            return TStringWrapper(kw.get_tstring_value().dereference()).to_string()
    else:
        name, what = lua_getobjname(p, pc, c)
        if len(what) > 0 and what[0] == 'c':
            return name
    return "?"


def lua_getobjname(p, lastpc, reg):
    name = lua_getlocalname(p, reg + 1, lastpc)
    if name is not None:
        return name, "local"
    pc = lua_findsetreg(p, lastpc, reg)
    if pc != -1:
        i = int(p["code"][pc])
        op = lua_op_getcode(i)
        if op == OP_MOVE:
            b = lua_op_getargb(i)
            if b < lua_op_getarga(i):
                return lua_getobjname(p, pc, b)
        elif op == OP_GETTABUP or op == OP_GETTABLE:
            k = lua_op_getargc(i)
            t = lua_op_getargb(i)
            vn = lua_getlocalname(p, t + 1, pc) if op == OP_GETTABLE else lua_upvalname(p, t)
            return lua_kname(p, pc, k), ("global" if vn is not None and vn == "_ENV" else "field")
        elif op == OP_GETUPVAL:
            return lua_upvalname(p, lua_op_getargb(i)), "upvalue"
        elif op == OP_LOADK or op == OP_LOADKX:
            b = lua_op_getargbx(i) if op == OP_LOADK else lua_op_getargax(int(p["code"][pc + 1]))
            tvw = TValueWrapper(p["k"][b])
            if tvw.is_string():
                return TStringWrapper(tvw.get_tstring_value().dereference()).to_string(), "constant"
        elif op == OP_SELF:
            k = lua_op_getargc(i)
            return lua_kname(p, pc, k), "method"
    return "?", ""


def lua_funcnamefromcode(L, ci):
    ciw = CallInfoWrapper(ci)
    p = TValueWrapper(ciw.get_func().dereference()).get_lua_closure_value()["p"]  # Calling function
    pc = ciw.get_current_pc()  # Calling instruction index
    i = int(p["code"][pc])  # Calling instruction
    if ciw.is_hooked():
        return "?", "hook"
    opcode = lua_op_getcode(i)
    if opcode == OP_CALL or opcode == OP_TAILCALL:
        return lua_getobjname(p, pc, lua_op_getarga(i))
    elif opcode == OP_TFORCALL:
        return "for iterator", "for iterator"
    elif opcode == OP_SELF or opcode == OP_GETTABUP or opcode == OP_GETTABLE:
        tm = TM_INDEX
    elif opcode == OP_SETTABUP or opcode == OP_SETTABLE:
        tm = TM_NEWINDEX
    elif opcode == OP_ADD or opcode == OP_SUB or opcode == OP_MUL or opcode == OP_MOD or opcode == OP_POW or opcode == OP_DIV or\
            opcode == OP_IDIV or opcode == OP_BAND or opcode == OP_BOR or opcode == OP_BXOR or opcode == OP_SHL or opcode == OP_SHR:
        offset = lua_op_getcode(i) - OP_ADD
        tm = offset + TM_ADD
    elif opcode == OP_UNM:
        tm = TM_UNM
    elif opcode == OP_BNOT:
        tm = TM_BNOT
    elif opcode == OP_LEN:
        tm = TM_LEN
    elif opcode == OP_CONCAT:
        tm = TM_CONCAT
    elif opcode == OP_EQ:
        tm = TM_EQ
    elif opcode == OP_LT:
        tm = TM_LT
    elif opcode == OP_LE:
        tm = TM_LE
    else:
        return "?", ""
    return TStringWrapper(lua_getglobalstate(L)["tmname"][tm].dereference()).to_string(), "metamethod"


def lua_getinfo(L, what, ci):
    ar = LuaDebugInfo()
    if what[0] == '>':
        ci = None
        func = L["top"] - 1
        what = what[1:]
    else:
        assert ci is not None
        func = ci["func"]
    t = TValueWrapper(func.dereference())
    assert t.is_function(), "function expected"
    cl = t.get_closure_value() if t.is_closure() else None

    # expand of lua_auxgetinfo(L, what, ar, cl, ci)
    ciw = CallInfoWrapper(ci) if ci is not None else None
    for i in range(0, len(what)):
        ch = what[i]
        if ch == 'S':
            if cl is None or cl["c"]["tt"] == LUA_TCCL:
                ar.source = "=[C]"
                ar.linedefined = -1
                ar.lastlinedefined = -1
                ar.what = "C"
                if cl is not None:
                    ar.address = cl["c"]["f"]
                else:
                    assert t.is_light_c_function()
                    ar.address = t.get_light_c_function()
            else:
                p = cl["l"]["p"]
                ar.source = TStringWrapper(p["source"].dereference()).to_string() if p["source"] else "=?"
                ar.linedefined = p["linedefined"]
                ar.lastlinedefined = p["lastlinedefined"]
                ar.what = "main" if ar.linedefined == 0 else "Lua"
                ar.short_src = lua_chunkid(ar.source, LUA_IDSIZE)
        elif ch == 'l':
            ar.currentline = ciw.get_current_line() if ciw is not None and ciw.is_lua() else -1
        elif ch == 'u':
            ar.nups = 0 if cl is None else cl["c"]["nupvalues"]
            if cl is None or cl["c"]["tt"] == LUA_TCCL:
                ar.isvararg = 1
                ar.nparams = 0
            else:
                ar.isvararg = cl["l"]["p"]["is_vararg"]
                ar.nparams = cl["l"]["p"]["numparams"]
        elif ch == 't':
            ar.istailcall = ciw.is_tailcall() if ciw is not None else False
        elif ch == 'n':
            ar.name = "?"
            ar.namewhat = ""
            if ciw is None:
                pass
            elif ciw.is_finalizer():
                ar.name = "__gc"
                ar.namewhat = "metamethod"
            elif (not ciw.is_tailcall()) and ciw.get_prev().is_lua():
                ar.name, ar.namewhat = lua_funcnamefromcode(L, ciw.get_prev().value)
    return ar


def lua_unboundsearch(t, j):
    i = j
    j += 1
    while not TValueWrapper(lua_rawgeti(t, j)).is_nil():
        i = j
        if j > int(math.floor(2147483647 / 2)):
            i = 1
            while not TValueWrapper(lua_rawgeti(t, i)).is_nil():
                i += 1
            return i - 1
        j *= 2
    while j - i > 1:
        m = int(math.floor((i + j) / 2))
        if TValueWrapper(lua_rawgeti(t, m)).is_nil():
            j = m
        else:
            i = m
    return i


def lua_getn(t):
    j = long(t["sizearray"])
    if j > 0 and TValueWrapper(t["array"][j - 1]).is_nil():
        i = 0
        while j - i > 1:
            m = math.floor(i + j) / 2
            if TValueWrapper(t["array"][m - 1]).is_nil():
                j = m
            else:
                i = m
        return i
    if t["lastfree"] == 0:
        return j
    return lua_unboundsearch(t, j)


def lua_rawlen(obj):
    if obj.type.unqualified().target().tag != "Table":
        t = TValueWrapper(obj)
        if t.is_short_string():
            return t.get_tstring_value()["shrlen"]
        elif t.is_long_string():
            return t.get_tstring_value()["u"]["lnglen"]
        elif t.is_full_userdata():
            return t.get_userdata_value()["len"]
        elif t.is_table():
            return lua_getn(t.get_table_value())
        return 0
    return lua_getn(obj)


def lua_getmetatable(obj):
    t = TValueWrapper(obj)
    tag = t.get_type_tag_no_variants()
    if tag == LUA_TTABLE:
        return t.get_table_value()["metatable"]
    elif tag == LUA_TUSERDATA:
        return t.get_userdata_value()["metatable"]
    return None


# Pretty printers


def escape_string(s):
    return s.replace('\n', "\\n").replace('\r', "\\r").replace('"', "\\\"").replace('\t', "\\t")


class TStringPrinter:
    def __init__(self, value):
        self.value = TStringWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return
        yield "len", long(self.value.get_length())
        yield "buf", self.value.get_buffer()

    def to_string(self, show_string=False):
        if self.value.value.address == 0:
            return "nullptr"
        if show_string:
            return "<lua_string> \"%s\"" % escape_string(self.value.to_string())
        return "<lua_string>"


class TStringPointerPrinter(TStringPrinter):
    def __init__(self, value):
        TStringPrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self, show_string=False):
        if self.addr == 0:
            return "(TString *) 0x%x" % self.addr
        return "(TString *) 0x%x %s" % (self.addr, TStringPrinter.to_string(self, show_string=show_string))


class UDataPrinter:
    def __init__(self, value):
        self.value = UDataWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return
        yield "len", long(self.value.get_length())
        yield "buf", self.value.get_buffer()
        yield "metatable", self.value.get_metatable()

    def to_string(self):
        if self.value.value.address == 0:
            return "nullptr"
        return "<lua_userdata>"


class UDataPointerPrinter(UDataPrinter):
    def __init__(self, value):
        UDataPrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self):
        if self.addr == 0:
            return "(Udata *) 0x%x" % self.addr
        return "(Udata *) 0x%x %s" % (self.addr, UDataPrinter.to_string(self))


class CClosurePrinter:
    def __init__(self, value):
        self.value = CClosureWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return
        yield "func", self.value.get_function()
        for i in range(0, self.value.get_upvalue_count()):
            yield "upval_%d" % (i + 1), TValuePointerPrinter(pointer_of(self.value.get_upvalue(i))).to_string(with_address=True,
                                                                                                              show_string=True)

    def to_string(self):
        if self.value.value.address == 0:
            return "nullptr"
        return "<lua_cclosure>"


class CClosurePointerPrinter(CClosurePrinter):
    def __init__(self, value):
        CClosurePrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self):
        if self.addr == 0:
            return "(CClosure *) 0x%x" % self.addr
        return "(CClosure *) 0x%x %s" % (self.addr, CClosurePrinter.to_string(self))


class LClosurePrinter:
    def __init__(self, value):
        self.value = LClosureWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return
        yield "proto", self.value.get_prototype()
        for i in range(0, self.value.get_upvalue_count()):
            yield "upval_%d" % (i + 1), TValuePointerPrinter(pointer_of(self.value.get_upvalue(i))).to_string(with_address=True,
                                                                                                              show_string=True)

    def to_string(self):
        if self.value.value.address == 0:
            return "nullptr"
        return "<lua_lclosure>"


class LClosurePointerPrinter(LClosurePrinter):
    def __init__(self, value):
        LClosurePrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self):
        if self.addr == 0:
            return "(LClosure *) 0x%x" % self.addr
        return "(LClosure *) 0x%x %s" % (self.addr, LClosurePrinter.to_string(self))


class TablePrinter:
    # Visited = None

    def __init__(self, value):
        self.value = TableWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return

        # visited_owner = False
        # if TablePrinter.Visited is None:
        #     TablePrinter.Visited = set()
        #     visited_owner = True

        # addr = long(self.value.value.address)
        # if addr in TablePrinter.Visited:
        #     return
        # TablePrinter.Visited.add(addr)

        try:
            if self.value.get_metatable() != 0:
                yield "@metatable", self.value.get_metatable()
            for k, v in self.value:
                vstr = TValuePointerPrinter(v).to_string(with_address=True, show_string=True)
                if isinstance(k, gdb.Value):
                    wrappered_key = TValueWrapper(k)
                    if wrappered_key.is_number():
                        yield "[%s]" % str(wrappered_key.get_number()), vstr
                    elif wrappered_key.is_string():
                        wrappered_str = TStringWrapper(wrappered_key.get_tstring_value().dereference())
                        yield "[\"%s\"]" % escape_string(wrappered_str.to_string()), vstr
                    else:
                        yield TValuePointerPrinter(k.address).to_string(), vstr
                else:
                    yield "[%d]" % k, vstr
        finally:
            # if visited_owner:
            #     TablePrinter.Visited = None
            # else:
            #     TablePrinter.Visited.remove(addr)
            pass

    def to_string(self):
        if self.value.value.address == 0:
            return "nullptr"
        return "<lua_table>"


class TablePointerPrinter(TablePrinter):
    def __init__(self, value):
        TablePrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self):
        if self.addr == 0:
            return "(Table *) 0x%x" % self.addr
        return "(Table *) 0x%x %s" % (self.addr, TablePrinter.to_string(self))


class ProtoPrinter:
    def __init__(self, value):
        self.value = ProtoWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return
        if self.value.is_vararg():
            yield "args", "%d (varargs)" % self.value.get_arg_count()
        else:
            yield "args", "%d" % self.value.get_arg_count()
        yield "source", TStringPointerPrinter(self.value.get_source()).to_string(show_string=True)
        yield "linedefined", self.value.get_line_defined()
        for i, v in self.value.upvalues():
            yield "upval_%d" % i, TStringPointerPrinter(v["name"]).to_string(show_string=True)
        for i, v in self.value.local_values():
            yield "local_%d" % i, TStringPointerPrinter(v["varname"]).to_string(show_string=True)

    def to_string(self):
        if self.value.value.address == 0:
            return "nullptr"
        return "<lua_prototype>"


class ProtoPointerPrinter(ProtoPrinter):
    def __init__(self, value):
        ProtoPrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self):
        if self.addr == 0:
            return "(Proto *) 0x%x" % self.addr
        return "(Proto *) 0x%x %s" % (self.addr, ProtoPrinter.to_string(self))


class TValuePrinter:
    def __init__(self, value):
        self.value = TValueWrapper(value)

    def children(self):
        if self.value.value.address == 0:
            return

        if self.value.is_thread():
            yield "gc", self.value.get_thread_value()
        elif self.value.is_prototype():
            yield "gc", self.value.get_prototype_value()
        elif self.value.is_dead_key():
            yield "gc", self.value.get_gc_union()
        elif self.value.is_string():
            yield "gc", self.value.get_tstring_value()
        elif self.value.is_table():
            yield "gc", self.value.get_table_value()
        elif self.value.is_c_closure():
            yield "gc", self.value.get_c_closure_value()
        elif self.value.is_lua_closure():
            yield "gc", self.value.get_lua_closure_value()
        elif self.value.is_full_userdata():
            yield "gc", self.value.get_userdata_value()
        return

    def to_string(self, with_address=False, show_string=False):
        if self.value.value.address == 0:
            return "nullptr"

        if self.value.is_nil():
            return "<lua_nil> nil"
        elif self.value.is_boolean():
            return "<lua_bool> %s" % ("false" if self.value.is_false() else "true")
        elif self.value.is_integer():
            return "<lua_int> %s" % str(self.value.get_integer())
        elif self.value.is_float():
            return "<lua_float> %s" % str(self.value.get_float())
        elif self.value.is_light_userdata():
            return "<lua_lightuserdata> 0x%x" % long(self.value.get_light_userdata())
        elif self.value.is_light_c_function():
            return "<lua_cfunction> %s" % str(self.value.get_light_c_function())
        elif self.value.is_thread():
            if with_address:
                return "<lua_thread^> 0x%x" % long(self.value.get_thread_value())
            return "<lua_thread^>"
        elif self.value.is_prototype():
            if with_address:
                return "<lua_prototype^> 0x%x" % long(self.value.get_prototype_value())
            return "<lua_prototype^>"
        elif self.value.is_dead_key():
            if with_address:
                return "<lua_deadkey^> 0x%x" % long(self.value.get_dead_key_value())
            return "<lua_deadkey^>"
        elif self.value.is_string():
            ts = self.value.get_tstring_value()
            ret = "<lua_string^>"
            if with_address:
                ret += " 0x%x" % long(ts)
            if show_string:
                ret += " \"%s\"" % escape_string(TStringWrapper(ts.dereference()).to_string())
            return ret
        elif self.value.is_table():
            if with_address:
                return "<lua_table^> 0x%x" % long(self.value.get_table_value())
            return "<lua_table^>"
        elif self.value.is_lua_closure():
            if with_address:
                return "<lua_lclosure^> 0x%x" % long(self.value.get_lua_closure_value())
            return "<lua_lclosure^>"
        elif self.value.is_c_closure():
            if with_address:
                return "<lua_cclosure^> 0x%x" % long(self.value.get_c_closure_value())
            return "<lua_cclosure^>"
        elif self.value.is_full_userdata():
            if with_address:
                return "<lua_userdata^> 0x%x" % long(self.value.get_userdata_value())
            return "<lua_userdata^>"
        return "<lua_?>"


class TValuePointerPrinter(TValuePrinter):
    def __init__(self, value):
        TValuePrinter.__init__(self, value.dereference())
        self.addr = long(value)

    def to_string(self, with_address=False, show_string=False):
        if self.addr == 0:
            return "(TValue *) 0x%x" % self.addr
        return "(TValue *) 0x%x %s" % (self.addr, TValuePrinter.to_string(self, with_address=with_address, show_string=show_string))


# Functions


class LuaGetGlobalState(gdb.Function):
    """lua_getglobalstate(L)
Returns global state from current thread. C Api: G"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getglobalstate")

    def invoke(self, L):
        return lua_getglobalstate(L)


class LuaNilObject(gdb.Function):
    """lua_nilobject()
Returns global nil object. C Api: luaO_nilobject"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_nilobject")

    def invoke(self):
        return lua_nilobject()


class LuaIndex2Value(gdb.Function):
    """lua_index2addr(L, idx)
Returns object from specific stack index. C Api: index2addr"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_index2value")

    def invoke(self, L, idx):
        return lua_index2value(L, long(idx))


class LuaRawGet(gdb.Function):
    """lua_rawget(table, key)
Returns object from table by key. C Api: lua_rawget"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_rawget")

    def invoke(self, table, idx):
        return lua_rawget(table, idx)


class LuaRawGetI(gdb.Function):
    """lua_rawgeti(table, idx)
Returns object from table object by int key. C Api: lua_rawgeti"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_rawgeti")

    def invoke(self, table, idx):
        return lua_rawgeti(table, idx)


class LuaRawGetS(gdb.Function):
    """lua_rawgets(table, key)
Returns object from table object by string key. Note that this method is slow."""

    def __init__(self):
        gdb.Function.__init__(self, "lua_rawgets")

    def invoke(self, table, key):
        return lua_rawgets(table, key)


class LuaRawLen(gdb.Function):
    """lua_rawlen(val)
Returns length or size from object. C Api: lua_rawlen."""

    def __init__(self):
        gdb.Function.__init__(self, "lua_rawlen")

    def invoke(self, val):
        return lua_rawlen(val)


class LuaGetCachedString(gdb.Function):
    """lua_getcachedstring(L, str)
Returns a cached string from current lua state."""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getcachedstring")

    def invoke(self, L, s):
        ret = lua_getcachedstring(L, s)
        if ret is None:
            return False
        return ret


class LuaGetRegistryTable(gdb.Function):
    """lua_getregistrytable(L)
Returns the global registry table."""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getregistrytable")

    def invoke(self, L):
        return lua_getregistrytable(L)


class LuaGetGlobalTable(gdb.Function):
    """lua_getglobaltable(L)
Returns the global table."""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getglobaltable")

    def invoke(self, L):
        return lua_getglobaltable(L)


class LuaGetStack(gdb.Function):
    """lua_getstack(L, idx)
Returns the stack frame at 'idx'. C Api: lua_getstack"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getstack")

    def invoke(self, L, idx):
        return lua_getstack(L, idx)


class LuaGetLocal(gdb.Function):
    """lua_getlocal(L, frame, idx)
Returns the local variable at index 'idx' of the specific stack frame 'frame'. C Api: lua_getlocal"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getlocal")

    def invoke(self, L, frame, idx):
        ci = lua_getstack(L, frame)
        ret = lua_getlocal(L, ci, idx)
        if not ret:
            raise RuntimeError("Local variable not found at idx %d" % idx)
        return ret[1]


class LuaGetLocalName(gdb.Function):
    """lua_getlocalname(L, frame, idx)
Returns the name of the local variable at index 'idx' of the specific stack frame 'frame'. C Api: lua_getlocal"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getlocalname")

    def invoke(self, L, frame, idx):
        ci = lua_getstack(L, frame)
        ret = lua_getlocal(L, ci, idx)
        if not ret:
            raise RuntimeError("Local variable not found at idx %d" % idx)
        return ret[0]


class LuaGetMetatable(gdb.Function):
    """lua_getmetatable(obj)
Returns the metatable of the specific object. Returns 0 if no metatable. C Api: lua_getmetatable"""

    def __init__(self):
        gdb.Function.__init__(self, "lua_getmetatable")

    def invoke(self, obj):
        ret = lua_getmetatable(obj)
        return False if ret is None else ret


# Commands


class GLuaTraceback(gdb.Command):
    """glua_traceback [lua_State*]
Print the stack traceback of the lua_State."""

    def __init__(self):
        gdb.Command.__init__(self, "glua_traceback", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, args, _from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 0:
            t = gdb.lookup_type("lua_State").pointer()
            L = gdb.parse_and_eval(argv[0]).cast(t)
        else:
            L = gdb.parse_and_eval("L")

        idx = 0
        ci = CallInfoWrapper(L["ci"].dereference())
        print("stack traceback:")
        while ci.value.address != L["base_ci"].address:
            ar = lua_getinfo(L, "nSlt", ci.value)
            print("\t#%d  %s" % (idx, str(ar)))
            idx += 1
            ci = ci.get_prev()


class GLuaStackInfo(gdb.Command):
    """glua_stackinfo [lua_State* [index]]
Print the stack info and all the variables of the current stack frame or the specific stack frame."""

    def __init__(self):
        gdb.Command.__init__(self, "glua_stackinfo", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, args, _from_tty):
        argv = gdb.string_to_argv(args)
        idx = 0
        if len(argv) > 0:
            t = gdb.lookup_type("lua_State").pointer()
            L = gdb.parse_and_eval(argv[0]).cast(t)
            if len(argv) > 1:
                idx = int(gdb.parse_and_eval(argv[1]))
        else:
            L = gdb.parse_and_eval("L")

        i = 0
        ci = CallInfoWrapper(L["ci"].dereference())
        while ci.value.address != L["base_ci"].address and i < idx:
            ci = ci.get_prev()
            i += 1
        if ci.value.address == L["base_ci"].address or i != idx:
            raise RuntimeError("Frame index out of range")

        ar = lua_getinfo(L, "nSlt", ci.value)
        print("#%d  %s" % (idx, str(ar)))

        func = ci.get_func()
        t = TValueWrapper(func.dereference())

        # Native function
        if t.is_light_c_function() or t.is_c_closure():
            print("\nNative stack values:")
            base = ci.get_base()
            if idx == 0:
                top = L["top"]
            else:
                next = ci.get_next()
                if next.is_lua():
                    top = next.get_func() + 1
                else:
                    top = next.get_base()
            p = top - 1
            while p >= base:
                print("\t#%d  %s" % (p - base + 1, TValuePointerPrinter(p).to_string(with_address=True, show_string=True)))
                p = p - 1

            if t.is_c_closure():
                cl = t.get_c_closure_value()
                nupvalues = cl["nupvalues"]
                if nupvalues > 0:
                    print("\nUpvalues:")
                    for i in range(0, nupvalues):
                        upval = cl["upvalue"][i]
                        print("\t#%d  %s" % (i, TValuePointerPrinter(upval.address).to_string(with_address=True, show_string=True)))
        else:  # Lua function
            assert ci.is_lua()

            # arguments
            f = t.get_lua_closure_value()["p"]
            nparams = f["numparams"]
            nvarparams = ((ci.get_lua_base() - 1) - ci.get_func()) - nparams

            if not (nparams == 0 and nvarparams == 0):
                print("\nParameters:")
                for i in range(0, nparams):
                    val = ci.get_lua_base() + i
                    name = lua_getlocalname(f, i + 1, ci.get_current_pc())
                    if name is None:
                        limit = L["top"] if ci.value.address == L["ci"] else ci.get_next().get_func()
                        if limit - ci.get_lua_base() >= i + 1 > 0:
                            name = "(*temporary)"
                        else:
                            name = "(?)"
                    print("\t#%d  %s = %s" % (i + 1, name, TValuePointerPrinter(val).to_string(with_address=True, show_string=True)))

                for i in range(-nvarparams, 0):
                    val = ci.get_lua_base() + i
                    print("\t#%d  (*vararg) = %s" % (i, TValuePointerPrinter(val).to_string(with_address=True, show_string=True)))

            # local variables
            if idx == 0:
                top = L["top"]
            else:
                next = ci.get_next()
                if next.is_lua():
                    top = next.get_func()
                else:
                    top = next.get_base() - 1
            loc_base = ci.get_lua_base() + nparams

            if top - loc_base > 1:
                print("\nLocals:")
                for i in range(0, top - loc_base):
                    val = ci.get_lua_base() + nparams + i
                    name = lua_getlocalname(f, i + 1 + nparams, ci.get_current_pc())
                    if name is None:
                        limit = L["top"] if ci.value.address == L["ci"] else ci.get_next().get_func()
                        if limit - ci.get_lua_base() >= i + 1 > 0:
                            name = "(*temporary)"
                        else:
                            name = "(?)"
                    print("\t#%d  %s = %s" % (i + 1 + nparams, name, TValuePointerPrinter(val).to_string(with_address=True,
                                                                                                         show_string=True)))

            # upvalues
            cl = t.get_lua_closure_value()
            nupvalues = cl["nupvalues"]
            if nupvalues > 0:
                print("\nUpvalues:")
                for i in range(0, nupvalues):
                    upval = cl["upvals"][i]["v"]
                    name = lua_upvalname(f, i)
                    print("\t#%d  %s = %s" % (i + 1, name, TValuePointerPrinter(upval).to_string(with_address=True, show_string=True)))


class GLuaObjectInfo(gdb.Command):
    """glua_objectinfo [lua_State*]
Print the memory usage of all the gc objects."""

    def __init__(self):
        gdb.Command.__init__(self, "glua_objectinfo", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, args, _from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 0:
            t = gdb.lookup_type("lua_State").pointer()
            L = gdb.parse_and_eval(argv[0]).cast(t)
        else:
            L = gdb.parse_and_eval("L")

        G = lua_getglobalstate(L)

        s_string_count = 0
        s_string_size = 0
        l_string_count = 0
        l_string_size = 0
        table_count = 0
        table_size = 0
        userdata_count = 0
        userdata_size = 0
        proto_count = 0
        proto_size = 0
        coroutine_count = 0
        coroutine_size = 0
        c_closure_count = 0
        c_closure_size = 0
        l_closure_count = 0
        l_closure_size = 0

        tvalue_sizeof = gdb.lookup_type("TValue").sizeof
        tstring_sizeof = gdb.lookup_type("TString").sizeof
        table_sizeof = gdb.lookup_type("Table").sizeof
        userdata_sizeof = gdb.lookup_type("Udata").sizeof
        proto_sizeof = gdb.lookup_type("Proto").sizeof
        coroutine_sizeof = gdb.lookup_type("lua_State").sizeof
        c_closure_sizeof = gdb.lookup_type("CClosure").sizeof
        l_closure_sizeof = gdb.lookup_type("LClosure").sizeof
        upval_sizeof = gdb.lookup_type("UpVal").sizeof
        node_sizeof = gdb.lookup_type("Node").sizeof
        instruction_sizeof = gdb.lookup_type("Instruction").sizeof
        proto_ptr_sizeof = gdb.lookup_type("Proto").pointer().sizeof
        int_sizeof = gdb.lookup_type("int").sizeof
        locvar_sizeof = gdb.lookup_type("LocVar").sizeof
        upvaldesc_sizeof = gdb.lookup_type("Upvaldesc").sizeof
        callinfo_sizeof = gdb.lookup_type("CallInfo").sizeof

        cnt = 0
        tu = gdb.lookup_type("union GCUnion").pointer()
        obj = G["allgc"].cast(tu)
        while obj:
            tag = obj["gc"]["tt"]
            tnov = tag & 0x0F
            if tnov == LUA_TSTRING:
                ts = TStringWrapper(obj["ts"])
                if tag == LUA_TSHRSTR:
                    s_string_size += ts.get_length() + tstring_sizeof
                    s_string_count += 1
                else:
                    l_string_size += ts.get_length() + tstring_sizeof
                    l_string_count += 1
            elif tnov == LUA_TUSERDATA:
                us = UDataWrapper(obj["u"])
                userdata_size += us.get_length() + userdata_sizeof
                userdata_count += 1
            elif tnov == LUA_TFUNCTION:
                cl = obj["cl"]
                if tag == LUA_TCCL:
                    upvalues = max(1, int(cl["c"]["nupvalues"]))
                    c_closure_size += tvalue_sizeof * (upvalues - 1) + c_closure_sizeof
                    c_closure_count += 1
                else:
                    upvalues = max(1, int(cl["l"]["nupvalues"]))
                    l_closure_size += upval_sizeof * (upvalues - 1) + l_closure_sizeof
                    l_closure_count += 1
            elif tnov == LUA_TTABLE:
                table = obj["h"]
                array_count = table["sizearray"]
                node_count = (1 << int(table["lsizenode"]))
                table_size += tvalue_sizeof * array_count + table_sizeof
                if table["lastfree"]:
                    table_size += node_sizeof * node_count
                table_count += 1
            elif tnov == LUA_TPROTO:
                f = obj["p"]
                sz = f["sizecode"] * instruction_sizeof + f["sizep"] * proto_ptr_sizeof + f["sizek"] * tvalue_sizeof +\
                     f["sizelineinfo"] * int_sizeof + f["sizelocvars"] * locvar_sizeof + f["sizeupvalues"] * upvaldesc_sizeof
                proto_size += sz + proto_sizeof
                proto_count += 1
            elif tnov == LUA_TTHREAD:
                # CallInfo Chain
                l = obj["th"]
                ci = l["base_ci"]
                sz = 0
                while ci:
                    sz += callinfo_sizeof
                    ci = ci["next"]
                sz += l["stacksize"] * tvalue_sizeof
                coroutine_size += sz + coroutine_sizeof
                coroutine_count += 1

            cnt += 1
            obj = obj["gc"]["next"].cast(tu)

        print("GC Object Statistic:")
        print("\tUserdata:      \t%d (%d bytes)" % (userdata_count, userdata_size))
        print("\tTable:         \t%d (%d bytes)" % (table_count, table_size))
        print("\tPrototype:     \t%d (%d bytes)" % (proto_count, proto_size))
        print("\tCoroutine:     \t%d (%d bytes)" % (coroutine_count, coroutine_size))
        print("\tString:        \t%d (%d bytes)" % (s_string_count + l_string_count, s_string_size + l_string_size))
        print("\t  Short String:\t%d (%d bytes)" % (s_string_count, s_string_size))
        print("\t  Long String: \t%d (%d bytes)" % (l_string_count, l_string_size))
        print("\tClosure:       \t%d (%d bytes)" % (c_closure_count + l_closure_count, c_closure_size + l_closure_size))
        print("\t  C Closure:   \t%d (%d bytes)" % (c_closure_count, c_closure_size))
        print("\t  Lua Closure: \t%d (%d bytes)" % (l_closure_count, l_closure_size))
        print("Total %d objects" % cnt)
        print("      %d bytes" % (userdata_size + table_size + proto_size + coroutine_size + s_string_size + l_string_size +\
                                  c_closure_size + l_closure_size))


class GLuaBreak(gdb.Command):
    """glua_break [lua_State*] filename line
Create a read watch breakpoint in the bytecode of function prototype at the specific source location."""

    def __init__(self):
        gdb.Command.__init__(self, "glua_break", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, args, _from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 2:
            t = gdb.lookup_type("lua_State").pointer()
            L = gdb.parse_and_eval(argv[0]).cast(t)
            filename = argv[1]
            line = int(argv[2])
        else:
            L = gdb.parse_and_eval("L")
            filename = argv[0]
            line = int(argv[1])

        G = lua_getglobalstate(L)

        # iterator all the Proto*
        cnt = 0
        tu = gdb.lookup_type("union GCUnion").pointer()
        obj = G["allgc"].cast(tu)
        while obj:
            tag = obj["gc"]["tt"]
            tnov = tag & 0x0F
            if tnov == LUA_TPROTO:
                f = obj["p"]
                if f["source"]:
                    ts_src = TStringWrapper(f["source"].dereference())
                    if int(ts_src.get_buffer()[0]) & 0xFF == ord('@'):
                        src = ts_src.to_string()
                        if os.path.basename(src[1:]) == filename:
                            # looking for lineinfo
                            if f["lineinfo"]:
                                for i in range(0, int(f["sizelineinfo"])):
                                    if f["lineinfo"][i] == line:
                                        if i < f["sizecode"]:
                                            cnt += 1
                                            if cnt >= 4:
                                                print("Too many breakpoint found, abort")
                                                return
                                            addr = f["code"] + i
                                            src_id = lua_chunkid(src, LUA_IDSIZE)
                                            print("Breakpoint at 0x%x: %s:%d" % (addr, src_id, line))
                                            gdb.execute("rwatch *(int*)%s" % addr)
                                            break
            obj = obj["gc"]["next"].cast(tu)


class GLuaBreakRegex(gdb.Command):
    """glua_breakr [lua_State*] regex line
Create a read watch breakpoint in the bytecode of function prototype at the specific source location."""

    def __init__(self):
        gdb.Command.__init__(self, "glua_breakr", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, args, _from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 2:
            t = gdb.lookup_type("lua_State").pointer()
            L = gdb.parse_and_eval(argv[0]).cast(t)
            regex = argv[1]
            line = int(argv[2])
        else:
            L = gdb.parse_and_eval("L")
            regex = argv[0]
            line = int(argv[1])

        regex = re.compile(regex, re.IGNORECASE)

        G = lua_getglobalstate(L)

        # iterator all the Proto*
        cnt = 0
        tu = gdb.lookup_type("union GCUnion").pointer()
        obj = G["allgc"].cast(tu)
        while obj:
            tag = obj["gc"]["tt"]
            tnov = tag & 0x0F
            if tnov == LUA_TPROTO:
                f = obj["p"]
                if f["source"]:
                    src = TStringWrapper(f["source"].dereference()).to_string()
                    if regex.match(src):
                        # looking for lineinfo
                        if f["lineinfo"]:
                            for i in range(0, int(f["sizelineinfo"])):
                                if f["lineinfo"][i] == line:
                                    if i < f["sizecode"]:
                                        cnt += 1
                                        if cnt >= 4:
                                            print("Too many breakpoint found, abort")
                                            return
                                        addr = f["code"] + i
                                        src_id = lua_chunkid(src, LUA_IDSIZE)
                                        print("Breakpoint at 0x%x: %s:%d" % (addr, src_id, line))
                                        gdb.execute("rwatch *(int*)%s" % addr)
                                        break
            obj = obj["gc"]["next"].cast(tu)


# Main


# register pretty printers
def printer_lookup_function(value):
    lookup_type = value.type
    if lookup_type is None:
        return None
    lookup_type = str(lookup_type)
    if re.match("^(struct )?(lua_TValue|TValue)$", lookup_type):
        return TValuePrinter(value)
    elif re.match(r"^StkId|((struct )?(TValue|lua_TValue)\s*\*)$", lookup_type):
        return TValuePointerPrinter(value)
    elif re.match("^(struct )?TString$", lookup_type):
        return TStringPrinter(value)
    elif re.match(r"^(struct )?TString\s*\*$", lookup_type):
        return TStringPointerPrinter(value)
    elif re.match("^(struct )?Udata$", lookup_type):
        return UDataPrinter(value)
    elif re.match(r"^(struct )?Udata\s*\*$", lookup_type):
        return UDataPointerPrinter(value)
    elif re.match("^(struct )?CClosure$", lookup_type):
        return CClosurePrinter(value)
    elif re.match(r"^(struct )?CClosure\s*\*$", lookup_type):
        return CClosurePointerPrinter(value)
    elif re.match("^(struct )?LClosure$", lookup_type):
        return LClosurePrinter(value)
    elif re.match(r"^(struct )?LClosure\s*\*$", lookup_type):
        return LClosurePointerPrinter(value)
    elif re.match("^(struct )?Table$", lookup_type):
        return TablePrinter(value)
    elif re.match(r"^(struct )?Table\s*\*$", lookup_type):
        return TablePointerPrinter(value)
    elif re.match("^(struct )?Proto$", lookup_type):
        return ProtoPrinter(value)
    elif re.match(r"^(struct )?Proto\s*\*$", lookup_type):
        return ProtoPointerPrinter(value)
    return None


gdb.pretty_printers.insert(0, printer_lookup_function)


# register functions
LuaGetGlobalState()
LuaNilObject()
LuaIndex2Value()
LuaRawGet()
LuaRawGetI()
LuaRawGetS()
LuaRawLen()
LuaGetCachedString()
LuaGetRegistryTable()
LuaGetGlobalTable()
LuaGetStack()
LuaGetLocal()
LuaGetLocalName()
LuaGetMetatable()


# register commands
GLuaTraceback()
GLuaStackInfo()
GLuaObjectInfo()
GLuaBreak()
GLuaBreakRegex()
