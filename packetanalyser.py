#! /usr/bin/env python

import sys
from os.path import isfile

# cli option parsing
# import getopt
import argparse

from packetreader.packetreader import readFile, readInterface

from protocols import analyse_sip
import pandas as pd


def read_packets_from_file(file):
    print("Reading file " + file)
    packets = readFile(file_name)
    return packets


def analyse_from_packets(packets, proto="", analysertp=False):
    if proto == "sip":
        sip_summary = analyse_sip(packets, analysertp=analysertp)
        for summary in sip_summary:
            if len(summary.keys()) == 0:
                continue
            print(pd.DataFrame(summary))


parser = argparse.ArgumentParser()
input_types = parser.add_mutually_exclusive_group()
input_types.add_argument(
    "-f", "--file", help="Name of file to read packets from")
input_types.add_argument(
    "-i", "--ifname", help="Name of interface to capture live packets from")

fopts = parser.add_argument_group('file options')

iopts = parser.add_argument_group('interface options')
iopts.add_argument(
    "-c", "--count", help="Number of packets to capture", type=int)
iopts.add_argument("-t", "--timeout",
                   help="Lenght of time to capture", type=int)

parser.add_argument(
    "-p", "--proto", help="Name of protocol to be analysed", action='append', choices=["sip", "rtp"], required=True)
args = parser.parse_args()

if args.file:
    file_name = args.file
    if(not isfile(file_name)):
        print("File " + file_name + ", can not be opened for reading!")
        exit(2)

    if "sip" in args.proto:
        analysertp = False
        if "rtp" in args.proto:
            analysertp = True
        packets = read_packets_from_file(file_name)
        analyse_from_packets(packets, proto="sip", analysertp=analysertp)
        exit()

if args.ifname:
    # if args.count and args.timeout:
    #     parser.error("Only one of -c or -t can be chosen")
    ifname = args.ifname
    print("Capturing on interface " + ifname)

    proto_map = {
        "sip": "port 5060",
        "http": "tcp port 80",
        "https": "tcp port 443"
    }
    bpf_filter = []
    for p in args.proto:
        bpf_filter.append(proto_map[p])

    bpf_filter = " or ".join(bpf_filter)
    try:
        c = readInterface(ifname, bpf_filter=bpf_filter)
        opts = {
            'packet_count': 0,
            'timeout': None,
        }
        if args.count:
            opts['packet_count'] = args.count
        if args.timeout:
            opts['timeout'] = args.timeout
        c.sniff(**opts)
        analyse_from_packets(c, proto="sip", analysertp=False)
        exit()
    except Exception as e:
        print(e)
