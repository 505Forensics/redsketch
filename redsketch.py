#!/usr/bin/env python
'''redsketch.py - Convert Mandiant Redline data into other formats '''

__author__ = "Matt Bromiley (@mbromileyDFIR)"
__license__ = "Apache License v2.0"
__version__ = "0.1.0"
__maintainer__ = "Matt Bromiley (@mbromileyDFIR)"
__email__ = "505forensics@gmail.com"
__status__ = "Development"

import argparse
import sqlite3
import time

def red_in(redline_file):
    """Parse the incoming Redline data"""
    entries = []
    conn = sqlite3.connect(redline_file)
    c = conn.cursor()
    for idx, row in enumerate(c.execute('SELECT * FROM Ports;')):
        # Test to see if timestamp exists
        if str(row[7]) == 'None':
            epoch = 'None'
            timestamp = 'None'
        else:
            epoch = int(time.mktime(time.strptime(str(row[7]), "%Y-%m-%d %H:%M:%SZ")))
            timestamp = row[7]

        # Test to see if process has a path, else return N/A
        if row[10]:
            path = row[10]
        else:
            path = 'N/A'

        # Test for protocol; TCP vs UDP will display different options
        if row[5] == 'UDP':
            # Options for UDP protocol
            if row[1]:
                line = ["UDP Connection {0}:{1} created by process {2} (PID: {3}), " \
                       "{4}, " \
                       "{5}, " \
                       "Port Opened, " \
                       "Process Path: {6}, " \
                       "Port State: {7}".format(row[1], row[2], row[9], row[8], epoch, timestamp, path, row[6])]
            else:
                line = ["UDP Connection over port {0}, " \
                       "created by process {1} (PID: {2})," \
                       "{3}," \
                       "{4}," \
                       "Port Opened," \
                       "Process Path: {5}," \
                       "Port State: {6}".format(row[2], row[9], row[8], epoch, timestamp, path, row[6])]
            entries.append(line)

        elif row[5] == 'TCP':
            if row[1]:
                line = ["TCP Connection {0}:{1} created by process {2} (PID: {3}), " \
                       "{4}, " \
                       "{5}, " \
                       "Port Opened, " \
                       "Process Path: {6}, " \
                       "Port State: {7}".format(row[1], row[2], row[9], row[8], epoch, timestamp, path, row[6])]
            else:
                line = ["TCP Connection over port {0}, " \
                       "created by process {1} (PID: {2})," \
                       "{3}," \
                       "{4}," \
                       "Port Opened," \
                       "Process Path: {5}," \
                       "Port State: {6}".format(row[2], row[9], row[8], epoch, timestamp, path, row[6])]
            entries.append(line)
        else:
            # Instead of simply failing silently, if there was an unknown protocol for
            # _whatever_ reason, print the problem and the line
            print 'Unknown protocol found on line {}'.format(idx)
            print row

    return entries
def main():
    """Main function, includes argparse, input direction, and output"""
    parser = argparse.ArgumentParser(description='Convert Mandiant Redline data into another format')
    # Input Options
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', metavar='FILE', help='MANS file to parse')

    group = parser.add_argument_group()
    group.add_argument('--headers', action='store_true', help="Enable headers on output")

    # Parse It!
    args = parser.parse_args()

    if args.headers:
        print "Message,Timestamp,DateTime,Timestamp Description,Extra Field 1,Extra Field 2"

    if args.file:
        output = red_in(args.file)
        for row in output:
            print row

if __name__ == '__main__':
    main()
