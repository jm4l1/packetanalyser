#! /usr/bin/env python

import sys
from os.path import isfile
import getopt
from packetreader.packetreader import readFile

from protocols import analyse_sip
import pandas as pd


def showMenu(name):
    print('Invalid usage specified')
    print('usage: %s [options]' % name)
    print('Options :')
    print('\t-f : Name of file to read')
    print('\t-i : Interface to read packets')
    print('\t-h : Show Help')


try:
    opts, args = getopt.getopt(sys.argv[1:], "hf:i:")

except getopt.GetoptError:
    showMenu(sys.argv[0])
    sys.exit(2)

for opt in opts:
    if opt[0] == '-h':
        showMenu(sys.argv[0])
        sys.exit()

    elif opt[0] == '-f':
        file_name = opt[1]
        if(file_name is None or file_name == ""):
            print("-f : File name must be given")
            exit(2)

        if(not isfile(file_name)):
            print("File " + file_name + ", can not be opened for reading!")
            exit(2)

        print("Reading file " + opt[1])
        packets = readFile(file_name)

    elif opt[0] == '-i':
        if_name = opt[1]
        if(if_name is None or if_name == ""):
            print("-f : File name must be given")
            exit(2)
        print("Reading interface " + if_name)

sip_summary = analyse_sip(packets)
for summary in sip_summary:
    if len(summary.keys()) == 0:
        continue
    print(pd.DataFrame(summary))
