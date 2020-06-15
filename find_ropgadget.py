from helpers import find_matching_lines, process2text
import re
from pwn import *


def rop_interactive(binaryName, outfile="rop.txt"):
    """
    Input:
        - binaryName: path to binary
        - outfile: name of the file where results will be written 
    Returns:
        - payload: ropchain assembled
    """
    p = process(f"ROPgadget --binary {binaryName}", shell=True)
    rops = process2text(p)

    done, add_mode = False, False
    payload = ""
    while not done:
        line = str(input("... "))[:-3]  # ugly way to remove added newline
        if "done" in line or "exit" in line or "quit" in line:
            break

        # writing payload to file
        if "write" in line:
            with open(outfile, "w") as f:
                f.write(payload)
            print(f"Payload written to file: {outfile}")
            return

        if "print" in line:
            print(f"Current payload is:\n {payload}")

        # look for a specific rop-gadget in the binary
        if "find" in line:
            if len(line.split()) <= 1:
                print("Please write the instruction to find.")
                continue
            curr_rop = " ".join(line.split()[1:])
            matches = find_matching_lines(rops, curr_rop)
            if len(matches) > 0:
                print("Found following matches:")
                for n, line in enumerate(matches):
                    print(f"{n}: {line}")
                print("Add any of these to the payload?"
                      " Enter number or \"no\".")
                add_mode = True
                continue
            else:
                print(f"Found no matches for \"{curr_rop}\" in binary")

        # add the specified ropgadget. Requires that the find command was used
        # as the immediate previous command. Should be used as "add 2" if the
        # wanted line number is number 2
        if "add" in line:
            if len(line.split()) <= 1:
                print("Please write the instruction to add.")
                continue
            if add_mode:
                if "".join(line.split()[1:]).isdigit():
                    addNumber = int("".join(line.split()[1:]))
                    print(f"Print added line number {addNumber}")
                    payload += matches[addNumber][2:-3] + "\n"
                else:
                    print("Please enter number in list")
        matches, add_mode = [], False

    return payload
