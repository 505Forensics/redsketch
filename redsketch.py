#!/usr/bin/env python
'''redsketch.py - Convert Mandiant Redline MANS data into Timesketch-friendly data '''

__author__ = "Matt Bromiley (@mbromileyDFIR)"
__license__ = "Apache License v2.0"
__version__ = "1.0.0-dev"
__maintainer__ = "Matt Bromiley (@mbromileyDFIR)"
__email__ = "505forensics@gmail.com"
__status__ = "Development"

import argparse
import sqlite3
import time

parseable_tables = [
    'Files',
    'Prefetch',
    'Ports'
]

def sysinfo(redline_file):
    sysinfo = {}
    '''System Information Parsing Function'''
    conn = sqlite3.connect(redline_file)
    c = conn.cursor()
    c.execute('SELECT Hostname,MachineName,SystemDate,TimeZoneStandard,TotalPhysicalMemory,OsString,OsBitness,InstallDate,Domain,LoggedInUser FROM SystemInformation;')
    attr_list = c.fetchone()
    sysinfo = {
        'Hostname' : attr_list[0],
        'Machine Name' : attr_list[1],
        'System Date' : attr_list[2],
        'Time Zone' : attr_list[3],
        'Total Physical Memory (bytes)' : attr_list[4],
        'Operating System' : attr_list[5],
        'Operating System Bitness' : attr_list[6],
        'InstallDate' : attr_list[7],
        'Domain' : attr_list[8],
        'Logged In User' : attr_list[9]
    }
    print sysinfo

def parse_it(data_type, redline_file):
    '''Master parsing function. Currently accepts unique values and then runs the corresponding code
    The will most likely be broken out into unique functions per table type'''
    entries = []
    conn = sqlite3.connect(redline_file)
    c = conn.cursor()
    # Files table parsing
    if data_type == 'files':
        for idx, row in enumerate(c.execute('SELECT FullPath,FileName,Size,Created,Modified,Accessed,Changed,MD5,SHA1,SHA256 from Files;')):
            epoch_created = int(time.mktime(time.strptime(str(row[3]), "%Y-%m-%d %H:%M:%SZ")))
            epoch_modified = int(time.mktime(time.strptime(str(row[4]), "%Y-%m-%d %H:%M:%SZ")))
            epoch_accessed = int(time.mktime(time.strptime(str(row[5]), "%Y-%m-%d %H:%M:%SZ")))
            epoch_changed = int(time.mktime(time.strptime(str(row[6]), "%Y-%m-%d %H:%M:%SZ")))

            # The following section deals with Unicode found in file names, such as Trademark and Copyright symbols.
            try:
                filename = row[1].encode('ascii','ignore')
            except AttributeError:
                filename = row[1]

            # The following section tests for each of the three possible hashes, and includes in the string if found. Otherwise, "No hash available" is displayed
            hashes = ''
            if row[7]:
                hashes += "{0} (MD5)".format(row[7])
            if row[8]:
                hashes += "{0} (SHA1)".format(row[8])
            if row[9]:
                hashes += "{0} (SHA256)".format(row[9])
            if not row[7] and not row[8] and not row[9]:
                hashes = "No hash available"

            line = ["File Created: {0},"
                    "{1},"
                    "{2},"
                    "File Creation,"
                    "File Size: {3} bytes,"
                    "Hash(es): {4}".format(filename, epoch_created, row[3], row[2], hashes)
                    ]

            entries.append(line)

            line = ["File Modified: {0},"
                    "{1},"
                    "{2},"
                    "File Modified,"
                    "File Size: {3} bytes,"
                    "Hash(es): {4}".format(filename, epoch_modified, row[3], row[2], hashes)
                    ]

            entries.append(line)

            line = ["File Accessed: {0},"
                    "{1},"
                    "{2},"
                    "File Accessed,"
                    "File Size: {3} bytes,"
                    "Hash(es): {4}".format(filename, epoch_accessed, row[3], row[2], hashes)
                    ]

            entries.append(line)

            line = ["File Entry Modified: {0},"
                    "{1},"
                    "{2},"
                    "File Entry Modified,"
                    "File Size: {3} bytes,"
                    "Hash(es): {4}".format(filename, epoch_changed, row[3], row[2], hashes)
                    ]

            entries.append(line)

        return entries

    # Prefetch table parsing
    if data_type == 'prefetch':
        for idx, row in enumerate(c.execute('SELECT Created,LastRun,ApplicationFileName,ApplicationFullPath FROM Prefetch;')):

            # Round 1 - Turn the Prefetch creationtime into a program execution event
            # Set the epoch and timestamp values for the creation event
            epoch = int(time.mktime(time.strptime(str(row[0]), "%Y-%m-%d %H:%M:%SZ")))
            timestamp = row[0]

            line = ["Program execution: {0}. Full Path: {1},"
                    "{2},"
                    "{3},"
                    "Prefetch File Created".format(row[2],row[3],epoch,timestamp)]

            entries.append(line)

            # Round 2 - Turn the Prefetch Last Run time into a program execution event
            epoch = int(time.mktime(time.strptime(str(row[1]), "%Y-%m-%d %H:%M:%SZ")))
            timestamp = row[1]

            line = ["Program execution: {0}. Full Path: {1},"
                    "{2},"
                    "{3},"
                    "Prefetch Last Run Time".format(row[2],row[3],epoch,timestamp)]
            entries.append(line)

        return entries

    # Port table parsing
    elif data_type == 'ports':
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
    '''Inspection function. Analyzes a MANS file, finds the tables with data'''
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
    group.add_argument('--sysinfo', metavar='FILE', help='MANS file to inspect\n\n\n')

    # Parser Options
    group = parser.add_argument_group()
    #group = parser.add_argument('--all', help='Enumerate and parse all available tables')
    group = parser.add_argument('-p', '--parsers', metavar='DATA', type=str, help='Tables to parse. Use "-p list" to see a list of available parsers')

    # Output options
    group = parser.add_argument_group()
    group.add_argument('--headers', action='store_true', help="Enable headers on output")

    # Parse It!
    args = parser.parse_args()

    if args.sysinfo:
        sysinfo(args.sysinfo)

    if args.inspect:
        # Set headers to false, just in case someone attempts to inspect the MANS file
        # and accidentally leaves the headers switch in
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
            parse_list = [item for item in args.parsers.split(',')]
            for item in parse_list:
                output = parse_it(item.lower(), args.file)
                for row in output:
                    print row

if __name__ == '__main__':
    main()
