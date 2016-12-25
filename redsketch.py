#!/usr/bin/env python
'''redsketch.py - Convert Mandiant Redline data into other formats '''

__author__ = "Matt Bromiley (@mbromileyDFIR)"
__license__ = "Apache License v2.0"
__version__ = "0.1.0"
__maintainer__ = "Matt Bromiley (@mbromileyDFIR)"
__email__ = "505forensics@gmail.com"
__status__ = "Development"

''' Timesketch output format:
message,timestamp,datetime,timestamp_desc,extra_field_1,extra_field_2
'''

import argparse
import sqlite3

def red_in(redline_file):
    entries = []
    conn = sqlite3.connect(redline_file)
    c = conn.cursor()
    #ID|LocalAddress|LocalPort|RemoteAddress|RemotePort|Protocol|PortState|Created|PortPID|PortProcessName|PortProcessPath|ProcessID|ItemSummaryID
    for row in c.execute('SELECT * FROM Ports;'):
        if row[5] == 'UDP':
            print "UDP"
            if row[1]:
                entries.insert(0,"Row 1 {} Found".format(row[0]))
            else:
                line = "UDP Connection over port {0}, created by process {1} (PID: {2}),'','{3},Port Opened".format(row[2],row[9],row[8],row[7])
                entries.insert(0,line)
        elif row[5] == 'TCP':
            print 'TCP'
        else:
            print 'Else'

    return entries
        #print 'Port opened between {0}:{1} and {2}:{3}'.format(row[1], row[2], row[3], row[4])

def main():
    parser = argparse.ArgumentParser(description='Convert Mandiant Redline data into another format')

    # Input Options
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', metavar='FILE', help='MANS file to parse')
    # group.add_argument('-d','--directory',metavar='DIR',help="Directory of MANS files")

    # Output Options - future-proofing with code from other scripts
    '''
    group = parser.add_argument_group()
    group.add_argument('-o','--output',metavar='OUTPUT',help='Output file [default is stdout]')
    group.add_argument('--json',action='store_true',help='Output in JSON')
    '''
    # Parse It!
    args = parser.parse_args()

    if args.file:
        output = red_in(args.file)
        print output

if __name__ == '__main__':
    main()