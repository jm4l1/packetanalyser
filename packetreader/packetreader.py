import pyshark


def readFile(filename):
    capture = pyshark.FileCapture(input_file=filename)
    return capture


def readInterface(if_name, bpf_filter=""):
    capture = pyshark.LiveCapture(interface=if_name, bpf_filter=bpf_filter)
    return capture
