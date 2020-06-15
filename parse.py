import sys
import argparse


def parse_args(argv=sys.argv):
    """
    Parses the arguments given to the program either as command line
    arguments or a configuration file.
        Input:
            - arguments to parse
        Returns:
            - Parsed arguments
    """
    argv = argv[1:]
    # placing arguments in config file to be read by argparse
    if "--config" in argv:
        configFile = argv[1]
        print(f"Using config file {configFile}")
        with open(configFile, "r") as f:
            argv = []
            for line in f.readlines():
                if line[0] == "#":
                    continue
                split = line.split("=")
                argv.append("--" + split[0])
                argv.append(split[1][:-1])

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--configfile",
                        help="Specify config file", metavar="FILE")
    parser.add_argument('--binaryName', type=str, required=True,
                        help='name of the binary to be analyzed')
    parser.add_argument('--approxbuffersize', default=20, type=int,
                        help='approximate size of the vulnerable buffer')
    parser.add_argument('--attack', default='all',
                        help='type of attack to attempt')
    parser.add_argument('--verbose', default='False',
                        choices=['True', 'False'], help='remove info printing')
    parser.add_argument('--goalFunction', default=False,
                        help='goal function to reach')
    parser.add_argument('--outfile', default="result.py",
                        help='file to read results to')
    parser.add_argument('--padChar', default="a",
                        help='character used for padding')
    parser.add_argument('--pathToOverflow', default=None,
                        help='Characters to enter before attempting to '
                        'overflow a buffer')

    args = parser.parse_args(argv)
    return args
