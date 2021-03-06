import argparse
import os
import sys
import packet_processing
import re


def main(argv):

    # Checking if the directory exists
    if not os.path.isdir(args.folder):
        print('"{}" does not exist'.format(args.folder), file=sys.stderr)
        sys.exit(-1)

    # Obtaining the mac_address from the folder
    # It must be considered that the mac address of the folder could not be in the correct format e.g. 0:26:29:0:77:ce but it is always valid
    # This problem is related to our folder
    myre = re.compile(r'(?:[0-9a-fA-F]:?){6,12}')
    mac_address = re.findall(myre, args.folder)
   
    # Verify path validity
    if not mac_address:
        print("Path {} not valid!".format(args.folder), file=sys.stderr)
        sys.exit(-1)
    
    mac_address = packet_processing.mac_address_fixer(mac_address[0])
    
    # Test already started, so skip some of the devices already anlaysed (binky dependent)
    file_filter = open('filtering_devices.txt', 'r')
    not_valid_devices =  file_filter.read().split(';')
    file_filter.close()

    if mac_address in not_valid_devices:
        print("Device {} already analysed skip...".format(mac_address))
        sys.exit(0)
    
    
    if args.packet_rate_final:
        print("Window size: {}".format(args.window))
        packet_processing.packet_rate_final(args.folder, mac_address, args.window)
    
    if args.packet_rate_fixed:
        print("Window size: {}".format(args.window))
        packet_processing.packet_rate_final_fixed_window(args.folder, mac_address, args.window)

    if args.bytes_rate_fixed:
        print("Window size: {}".format(args.window))
        packet_processing.bytes_rate_final_fixed_window(args.folder, mac_address, args.window)

    if args.destinations_contacted:
        if args.src_address is None:
            print('You must specify the source ip address', file=sys.stderr)
            sys.exit(-1)
        
        packet_processing.destinations_contacted(args.folder, args.src_address)

    if args.protocol:
        packet_processing.protocols_used(args.folder)

    if args.times:
        packet_processing.correlationCSV(args.folder)

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PCAP processer: It requires that all pcaps file are in a path which contains the mac address of the device to analyse (e.g. mac_address/subfolder/file.pcap or mac_address/file.pcap")

    # TODO change pcap with folder name
    parser.add_argument('-f', '--folder', metavar='<folder>',
                        help='folder containing pcap file to parse', type=str, required=True)
    parser.add_argument('--packet_rate_final', action='store_true',
                        help='packet rate considering all packets grouped by protocol')
    parser.add_argument('--packet_rate_fixed', action='store_true',
                        help='packet rate considering all packets grouped by protocol in fixed placed window')
    parser.add_argument('--bytes_rate_fixed', action='store_true',
                        help='bytes rate considering all packets grouped by protocol in fixed placed window')
    parser.add_argument('--window','-w', type=int,
                        help='window size in secs')
    parser.add_argument('--destinations_contacted', action='store_true',
                        help='destinations contacted by a src address')
    parser.add_argument('--protocol', action='store_true',
                        help='protocol to track')
    parser.add_argument('--times', action='store_true',
                        help='generate a CSV for all packets sorted by IP')
    parser.add_argument('--src_address', type=str,
                        help='src ip address')
    
    args = parser.parse_args()
    
    
    main(args)
