import numpy, sys, argparse
from ast import literal_eval


def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-s",
        "--string",
        required=True,
        help="String to compute hash for",
    )
    parser.add_argument(
        "-k",
        "--key",
        required=True,
        help="Hash key, example: 0xd",
    )

    args = parser.parse_args()

    edx = 0x00
    ror_count = 0

    esi = args.string

    key = int(args.key.replace("0x", ""),16)

    for eax in esi:
            edx = edx + ord(eax)
            if ror_count < len(esi)-1:
                    edx = ror_str(edx, int(key))
            ror_count += 1

    print("KEY: " + args.key)
    print("push {}".format(hex(edx)))