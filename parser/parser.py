"""

"""
import sys

from Capture import Packet, Capture


def get_file_data(file_path):
    cap_file_lines = []
    with open(file_path, 'rt') as cap_file:
        for line in cap_file:
            cap_file_lines.append(line)
    return cap_file_lines


def get_capture(dataLines):
    line1_offset = 2
    line2_offset = 3
    packet_offset = 4
    i = 1
    line1 = ''
    packets = []
    for line in dataLines:
        if i % packet_offset == line1_offset:
            line1 = line
        if i % packet_offset == line2_offset:
            packets.append(Packet(line1, line))
            line1 = ''
        i = i + 1
    return Capture(packets)


def main():
    if len(sys.argv) != 2:
        print("Usage: parser.py <filePath>")
    else:
        data_lines = get_file_data(sys.argv[1])
        capture = get_capture(data_lines)
        i = 1
        for packet in capture.packets:
            print('Frame ' + str(i))
            #if i <= 1:
            print(packet)
            i = i + 1
            #else:
            #    break


if __name__ == '__main__':
    main()
