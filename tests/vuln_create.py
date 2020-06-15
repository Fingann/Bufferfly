import argparse
import os
import sys


def set_up_parser(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Create binaries vulnerable "
                                                 "to buffer overflow")
    parser.add_argument('--bufferSize', type=int, default=20,
                        help='size of vulnerable buffer', dest='bufferSize')
    parser.add_argument('--overflowSize', type=int, default=40,
                        help='size of overflow', dest='overflowSize')
    parser.add_argument('--architecture', dest='architecture', default=32,
                        help='architecture of the created ', choices=[32, 64],
                        type=int)
    parser.add_argument('--goalFunctionName', type=str, default="spawn_shell",
                        dest='goalFunction', help="name of function spawning "
                        "shell. Give option \"off\" to not include this "
                        "function.")
    parser.add_argument('--name', dest='binaryName', type=str, default='vuln',
                        help='Name of the vulnerable binary to create')
    parser.add_argument('--nx', dest='nx', default=False,
                        help='Enable NX protection', action='store_true')
    parser.add_argument('--canary', dest='canary', default=False,
                        help='Enable stack canary', action='store_true')
    parser.add_argument('--relro', dest='relro', default="none", type=str,
                        help='Level of relro',
                        choices=["full", "partial", "none"])
    parser.add_argument('--pie', dest='pie', default=False,
                        help='Enable PIE', action='store_true')

    return parser.parse_args(args)


def create_makefile(ns):
    with open("makefile", "w") as f:
        f.write(f"CC=clang -m{ns.architecture}\n")
        # enabling/disabling stack canary
        if ns.canary:
            f.write("CFLAGS+=-fstack-protector\n")
        else:
            f.write("CFLAGS+=-fno-stack-protector\n")  # disable stack cookies

        # enabling/disabling stack execution
        if ns.nx:
            f.write("CFLAGS+=-Wl,-z,noexecstack\n")
        else:
            f.write("CFLAGS+=-z execstack\n")  # disable NX

        # enabling/disabling PIE
        if ns.pie:
            f.write("CFLAGS+=-fPIE -pie\n")
        else:
            f.write("CFLAGS+=-no-pie\n")

        # set level of relro
        if ns.relro == "none":
            f.write("CFLAGS+=-Wl,-z,norelro\n")
        elif ns.relro == "partial":
            f.write("CFLAGS+=-Wl,-z,relro\n")
        elif ns.relro == "full":
            f.write("CFLAGS+=-Wl,-z,relro,-z,now\n")

        # f.write("CFLAGS+=-g\n\n"  # TODO: find out what this means
        f.write(".PHONY: all, run, clean\n"
                f"all: {ns.binaryName}\n\n"
                f"{ns.binaryName}: {ns.binaryName}.c\n"
                "\t$(CC) $(CFLAGS) $^ -o $@\n\n"
                f"run: {ns.binaryName}\n"
                "\t./$^\n")


def create_source_code(binaryName, goalFunction, bufferSize, overflowSize):
    with open(f"{binaryName}.c", "w") as f:
        f.write("#include <stdlib.h>\n#include <stdio.h>\n"
                "#include <unistd.h>\n\n")

        if not goalFunction == "off":
            f.write(f"void {goalFunction}(void)\n"
                    "{\tsystem(\"/bin/sh\");\n}\n\n")

        f.write("int main(void)\n{\n"
                f"\tchar buf[{bufferSize}];\n"
                "\tsetvbuf(stdout, NULL, _IONBF, 0);\n"  # cleaning stdout
                "\tprintf(\"Get input...\");\n"
                f"\tread(STDIN_FILENO, buf, {bufferSize + overflowSize});\n"
                "\treturn 0;\n"
                "}\n")


def compile_binary(binaryName, nBytes):
    os.system("make")
    print(f"Created binary {binaryName}. The vulnerable buffer is {nBytes} "
          f"bytes large and {binaryName} has the following security "
          "properties:")
    os.system(f"checksec {binaryName}")


def clean_up(binaryName):
    os.system(f"rm {binaryName}.c makefile")


if __name__ == "__main__":
    ns = set_up_parser(sys.argv[1:])
    create_makefile(ns)
    create_source_code(ns.binaryName, ns.goalFunction, ns.bufferSize,
                       ns.overflowSize)
    compile_binary(ns.binaryName, ns.bufferSize)
    clean_up(ns.binaryName)
