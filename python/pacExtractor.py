#!/usr/bin/env python3

# This program is used for unpacking .pac file of Spreadtrum Firmware used in SPD Flash Tool for flashing.
# requires Python 3.7+
#
# Created : 31st January 2022
# Author  : HemanthJabalpuri
#
# This file has been put into the public domain.
# You can do whatever you want with this file.

# TODO: Add support for 4GB+ .pac firmware

import argparse
import os
import struct
import sys


PAC_HEADER_FMT = '48s I 512s 512s I I I I I I I 200s I I I 800s I H H'
FILE_HEADER_FMT = 'I 512s 512s 512s I I I I I I 5I 996s'
PAC_MAGIC = '0xfffafffa'
fiveSpaces = "     "

PAC_HEADER = {
    'szVersion': '',           # packet struct version
    'dwSize': 0,               # the whole packet size
    'productName': '',         # product name
    'firmwareName': '',        # product version
    'partitionCount': 0,       # the number of files that will be downloaded, the file may be an operation
    'partitionsListStart': 0,  # the offset from the packet file header to the array of PartitionHeaders start
    'dwMode': 0,
    'dwFlashType': 0,
    'dwNandStrategy': 0,
    'dwIsNvBackup': 0,
    'dwNandPageType': 0,
    'szPrdAlias': '',          # product alias
    'dwOmaDmProductFlag': 0,
    'dwIsOmaDM': 0,
    'dwIsPreload': 0,
    'dwReserved': 0,
    'dwMagic': 0,
    'wCRC1': 0,
    'wCRC2': 0
}

FILE_HEADER = {
    'length': 0,               # size of this struct itself
    'partitionName': '',       # file ID,such as FDL,Fdl2,NV and etc.
    'fileName': '',            # file name in the packet bin file. It only stores file name
    'szFileName': '',          # Reserved now
    'partitionSize': 0,        # file size
    'nFileFlag': 0,            # if "0", means that it need not a file, and
                               # it is only an operation or a list of operations, such as file ID is "FLASH"
                               # if "1", means that it need a file
    'nCheckFlag': 0,           # if "1", this file must be downloaded
                               # if "0", this file can not be downloaded
    'partitionAddrInPac': 0,   # the offset from the packet file header to this file data
    'dwCanOmitFlag': 0,        # if "1", this file can not be downloaded and not check it as "All files"
                               # in download and spupgrade tool.
    'dwAddrNum': 0,
    'dwAddr': 0,
    'dwReserved': 0            # Reserved for future, not used now
}

CRC16_TABLE = [
    0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
    0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
    0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
    0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
    0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
    0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
    0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
    0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
    0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
    0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
    0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
    0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
    0x2800, 0xe8c1, 0xe981, 0x2940, 0xeb01, 0x2bc0, 0x2a80, 0xea41,
    0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
    0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
    0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
    0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
    0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
    0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
    0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
    0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
    0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
    0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
    0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
    0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
    0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
    0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
    0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
    0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
    0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
    0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
    0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
]


# calculate/update CRC16
def calc_crc16(crc_base, s):
    for b in s:
        crc_base = (crc_base >> 8) ^ (CRC16_TABLE[(crc_base ^ b) & 0xff])
    return crc_base


def abort(message):
    print(message, file=sys.stderr)
    sys.exit()


def getString(name):
    return name.decode('utf-16').rstrip('\x00')


def printP(name, value):
    print(f'{name.ljust(13)} = {value}')


def printPacHeader(ph):
    printP('Version', ph['szVersion'])
    printP('Size', ph['dwSize'])
    printP('PrdName', ph['productName'])
    printP('FirmwareName', ph['firmwareName'])
    printP('FileCount', ph['partitionCount'])
    printP('FileOffset', ph['partitionsListStart'])
    printP('Mode', ph['dwMode'])
    printP('FlashType', ph['dwFlashType'])
    printP('NandStrategy', ph['dwNandStrategy'])
    printP('IsNvBackup', ph['dwIsNvBackup'])
    printP('NandPageType', ph['dwNandPageType'])
    printP('PrdAlias', ph['szPrdAlias'])
    printP('OmaDmPrdFlag', ph['dwOmaDmProductFlag'])
    printP('IsOmaDM', ph['dwIsOmaDM'])
    printP('IsPreload', ph['dwIsPreload'])
    printP('Magic', hex(ph['dwMagic']))
    printP('CRC1', ph['wCRC1'])
    printP('CRC2', ph['wCRC2'])
    print('\n')


def parsePacHeader(f, pacfile, debug):
    pacHeader = PAC_HEADER.copy()
    pacHeaderBin = struct.unpack(PAC_HEADER_FMT, f.read(struct.calcsize(PAC_HEADER_FMT)))

    i = 0
    for k, v in pacHeader.items():
        if str(v) == '0':
            pacHeader[k] = pacHeaderBin[i]
        else:
            pacHeader[k] = getString(pacHeaderBin[i])
        i += 1

    if pacHeader['szVersion'] != 'BP_R1.0.0':
        abort('Unsupported PAC version')
    if pacHeader['dwSize'] != os.stat(pacfile).st_size:
        abort("Bin packet's size is not correct")

    if debug:
        printPacHeader(pacHeader)

    return pacHeader


def verifyCRC16(f, ph, debug):
    if hex(ph['dwMagic']) == PAC_MAGIC:
        print('Checking CRC Part 1')
        f.seek(0)
        crcbuf = f.read(struct.calcsize(PAC_HEADER_FMT) - 4)
        crc1val = calc_crc16(0, crcbuf)
        if crc1val != ph['wCRC1']:
            if debug:
                print(f'Computed CRC1 = {crc1val}, CRC1 in PAC = {ph["wCRC1"]}')
            abort("CRC Check failed for CRC1\n")

    print('Checking CRC Part 2')
    f.seek(struct.calcsize(PAC_HEADER_FMT))
    bufsize = 64 * 1024
    totallen = ph['dwSize'] - struct.calcsize(PAC_HEADER_FMT)
    crc2val = 0
    while totallen > 0:
        if totallen < bufsize:
            bufsize = totallen
        crcbuf = f.read(bufsize)
        totallen -= bufsize
        crc2val = calc_crc16(crc2val, crcbuf)
    if crc2val != ph['wCRC2']:
        if debug:
            print(f'Computed CRC2 = {crc2val}, CRC2 in PAC = {ph["wCRC2"]}\n')
        abort('CRC Check failed for CRC2')

    print()


def printFileHeader(fh):
    printP('Size', fh['length'])
    printP('FileID', fh['partitionName'])
    printP('FileName', fh['fileName'])
    printP('FileSize', fh['partitionSize'])
    printP('FileFlag', fh['nFileFlag'])
    printP('CheckFlag', fh['nCheckFlag'])
    printP('DataOffset', fh['partitionAddrInPac'])
    printP('CanOmitFlag', fh['dwCanOmitFlag'])
    print()


def parseFiles(f, fileHeaders, debug):
    fileHeader = FILE_HEADER.copy()
    fileHeaderBin = struct.unpack(FILE_HEADER_FMT, f.read(struct.calcsize(FILE_HEADER_FMT)))

    i = 0
    for k, v in fileHeader.items():
        if str(v) == '0':
            fileHeader[k] = fileHeaderBin[i]
        else:
            fileHeader[k] = getString(fileHeaderBin[i])
        i += 1

    if fileHeader['length'] != struct.calcsize(FILE_HEADER_FMT):
        abort('Unknown Partition Header format found')

    if debug:
        printFileHeader(fileHeader)

    fileHeaders.append(fileHeader)


def extractFile(f, fh, outdir):
    tempsize = fh['partitionSize']
    if tempsize == 0:
        return
    print(f'{fiveSpaces}{fh["fileName"]}', end='')

    f.seek(fh['partitionAddrInPac'])
    size = 4096
    tsize = tempsize
    with open(os.path.join(outdir, fh['fileName']), 'wb') as ofile:
        while tempsize > 0:
            if tempsize < size:
                size = tempsize
            dat = f.read(size)
            tempsize -= size
            ofile.write(dat)
            print(f'\r{int(100 - ((100 * tempsize) / tsize))}%', end='')

    print(f'\r{fh["fileName"]}{fiveSpaces}')


def main(pacfile, outdir, debug, checkCRC16):
    if os.stat(pacfile).st_size < struct.calcsize(PAC_HEADER_FMT):
        abort(f'{pacfile} is not a PAC firmware.')
    if os.path.isfile(outdir):
        abort(f'file with name "{outdir}" exists')

    os.makedirs(outdir, exist_ok=True)

    with open(pacfile, 'rb') as f:
        # Unpack pac Header
        pacHeader = parsePacHeader(f, pacfile, debug)

        # Verify crc16
        if checkCRC16:
            verifyCRC16(f, pacHeader, debug)

        # Unpack partition headers
        fileHeaders = []
        f.seek(pacHeader['partitionsListStart'])
        for i in range(pacHeader['partitionCount']):
            parseFiles(f, fileHeaders, debug)

        # Extract partitions using partition headers
        print(f'\nExtracting to {outdir}\n')
        for i in range(pacHeader['partitionCount']):
            extractFile(f, fileHeaders[i], outdir)

    print('\nDone...')


if __name__ == '__main__':
    if not sys.version_info >= (3, 7):
        # Python 3.7 for keeping inserted order in dictionary
        # Python 3.6 for f-strings
        abort('Requires Python 3.7+')

    parser = argparse.ArgumentParser()
    parser.add_argument('pacfile', help='Spreadtrum .pac file')
    parser.add_argument('outdir',nargs='?', default=os.path.join(os.getcwd(), 'outdir'),
                        help='output directory to extract files')
    parser.add_argument('-d', dest='debug', action='store_true', help='enable debug output')
    parser.add_argument('-c', dest='checkCRC16', action='store_true', help='compute and verify CRC16')
    args = parser.parse_args()

    main(args.pacfile, args.outdir, args.debug, args.checkCRC16)
