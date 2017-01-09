#!/usr/bin/env python
'''redsketch.py - Convert Mandiant Redline data into other formats '''

__author__ = "Matt Bromiley (@mbromileyDFIR)"
__license__ = "Apache License v2.0"
__version__ = "0.2.0"
__maintainer__ = "Matt Bromiley (@mbromileyDFIR)"
__email__ = "505forensics@gmail.com"
__status__ = "Development"

import argparse
import sqlite3
import time

parseable_tables = [
    'Ports'
]

def parse_it(data_type, redline_file):
    '''Master parsing function. Currently accepts unique values and then runs the corresponding code
    The will most likely be broken out into unique functions per table type'''
    entries = []
    conn = sqlite3.connect(redline_file)
    c = conn.cursor()
    # Port table parsing
    if data_type == 'Ports':
        """Parse the incoming Redline data"""

        # Currently, the query selects all and the relevant fields are output.
        # This query could be refined to pull back only the fields of interest, and then just apply sequentially
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
                # Options for TCP protocol
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
    else:
        print "{} not found".format(data_type)

def inspect(redline_file, print_out):
    tables = []
    populated_tables = []
    conn = sqlite3.connect(redline_file)
    c = conn.cursor()

    # First, we want to gather the list of tables wihtin a MANS file. This list is actually fairly static, however I
    # we don't need to hardcode that list, in case FireEye makes a change
    for table in c.execute('SELECT name FROM sqlite_master WHERE type="table";'):
        tables.append(table[0].encode('ascii'))

    # Now, let's attempt to pull back one row for each table
    for table in tables:
        results = c.execute('SELECT  * from {0} LIMIT 1;'.format(table))
        # If we get a row back, then we have data within the table. Add this to the list of populated tables
        if results.fetchone():
            populated_tables.append(table)

    # Options to either print the inspection output, or simply pass the list back to the parsers. This enables the '--all' switch to use inspect to get a list of tables to parse
    if print_out:
        # Print block for inspection report
        print "*"*40
        print "MANS File Inspection Report:"
        print "File name: {}\n".format(redline_file)
        # Print block for table data
        print "TABLE DATA"
        print "  Total tables: {0}".format(len(tables))
        print "  Populated Tables: {0}\n".format(len(populated_tables))
        # Print block to list each populated table
        print "Populated Tables: "
        for table in sorted(populated_tables):
            print "  {}".format(table)
        # Print block to list tables available for conversion
        print "\nTables Currently Available for Conversion:"
        for table in parseable_tables:
            print "  {0}".format(table)
    else:
        return parseable_tables


def main():
    """Main function, includes argparse, input direction, and output"""
    parser = argparse.ArgumentParser(
        description='Convert Mandiant Redline data into Timesketch-friendly format',
        usage="%(prog)s [options]"
    )
    # Input Options
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', metavar='FILE', help='MANS file to parse')
    group.add_argument('--inspect', metavar='FILE', help='MANS file to inspect\n\n\n')

    # Parser Options
    group = parser.add_argument_group()
    #group = parser.add_argument('--all', help='Enumerate and parse all available tables')
    group = parser.add_argument('-p', '--parsers', metavar='DATA', help='Tables to Select (Comma separated). Use --all instead of -p to parse all tables. Use "list" to see a list of available table parsers')

    # Output options
    group = parser.add_argument_group()
    group.add_argument('--headers', action='store_true', help="Enable headers on output")

    # Parse It!
    args = parser.parse_args()

    if args.inspect:
        # Set headers to false, just in case someone attempts to inspect the MANS file
        # and accidentially leaves the headers switch in
        args.headers = False
        inspect(args.inspect, True)

    if args.headers:
        print "Message,Timestamp,DateTime,Timestamp Description,Extra Field 1,Extra Field 2"

    if args.file:
        if args.parsers == 'list':
            print "\nCurrently developed parsers include:"
            for table in sorted(parseable_tables):
                print table
            exit(0)
        if args.file and args.parsers:
            output = parse_it(args.parsers, args.file)
            for row in output:
                print row

if __name__ == '__main__':
    main()
