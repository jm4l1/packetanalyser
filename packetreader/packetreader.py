import pyshark


def readFile(filename):
    capture = pyshark.FileCapture(input_file=filename)
    return capture
