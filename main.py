#!/usr/bin/python

import sys
import csv
from collections import Counter
from typing import Dict, List
import numpy as np

UPLOAD = 0
DOWNLOAD = 1
NEGLIGIBLE_THRESHOLD = 10   # if a server sends < N packets during a period, ignore it
SERVER_LIMIT = 3    # analyze communication between localIP and up to N different servers
NO = 0
TIME = 1
SRC = 2
DST = 3
PROTO = 4
LENGTH = 5
INFO = 6


def main():
    args = sys.argv
    '''
    args: logfile.csv active_start_idx, active_end_idx, idle_start_idx, idle_end_idx, ip_address
    all indices are inclusive
    '''
    assert( len( args ) == 7 )
    filename = args[1]  # this is the name of the log, in CSV format
    activeStart = int( args[2] )
    activeEnd = int( args[3] )
    idleStart = int( args[4] )
    idleEnd = int( args[5] )
    localIP = args[6]

    with open( filename, 'rt', encoding='utf-8' ) as log, open('result.txt', 'w') as output:
        logReader = csv.reader( log )
        lines = list( logReader )
        assert ( 0 < int( x ) < len( lines ) for x in args[2:6] )

        # analyze ACTIVE period, return a list of logs clustered by servers
        output.write( "ANALYZE ACTIVE PERIOD\n" )
        activeDownLogList = preprocess( lines, localIP, activeStart, activeEnd, DOWNLOAD )
        for log in activeDownLogList:
            output.write( '%s ---> %s (%s) [%d packets]:\n' % ( log[0][SRC], localIP, log[0][PROTO], len( log ) ) )
            analyze( log, output )

        activeUpLogList = preprocess( lines, localIP, activeStart, activeEnd, UPLOAD )
        for log in activeUpLogList:
            output.write( '%s ---> %s (%s) [%d packets]:\n' % ( log[0][DST], localIP, log[0][PROTO], len( log ) ) )
            analyze( log, output )

        # analyze IDLE period, return a list of logs clustered by servers
        output.write( "\nANALYZE IDLE PERIOD\n" )
        idleDownLogList = preprocess( lines, localIP, idleStart, idleEnd, DOWNLOAD )
        for log in idleDownLogList:
            output.write( '%s ---> %s (%s) [%d packets]:\n' % ( log[0][SRC], localIP, log[0][PROTO], len( log ) ) )
            analyze( log, output )

        idleUpLogList = preprocess( lines, localIP, idleStart, idleEnd, UPLOAD )
        for log in idleUpLogList:
            output.write( '%s ---> %s (%s) [%d packets]:\n' % ( log[0][DST], localIP, log[0][PROTO], len( log ) ) )
            analyze( log, output )


'''filter log entries that:
1) has NO. between [start, end]
2) has correct stream direction with localIP
3) pick only top SERVER_LIMIT server IPs with the most common protocol
4) LEN != 0 
'''
def preprocess(
lines: List[List[str]],
        localIP: str, start: int, end: int, DIR: int ) -> List[List[str]]:

    d = DST if DIR == UPLOAD else SRC  # if we are uploading, pick top SERVER_LIMIT from DST, else SRC

    # filter by direction
    serverCnt = Counter()
    if DIR == UPLOAD:
        relevantLog = list(filter(lambda x: x[SRC] == localIP and 'LEN=0' not in x[INFO],
                            lines[start:end + 1]))
    else:   # DIR == DOWNLOAD
        relevantLog = list(filter(lambda x: x[DST] == localIP and 'LEN=0' not in x[INFO],
                            lines[start:end + 1]))

    # pick top SERVER_LIMIT servers
    for row in relevantLog:
        serverCnt[ row[d] ] += 1
    servers = serverCnt.most_common(SERVER_LIMIT)

    # filter by most common protocol for each server
    result = []
    protoCnt = Counter()
    for ( server, cnt ) in servers:
        if cnt < NEGLIGIBLE_THRESHOLD:
            continue
        temp = [ x for x in relevantLog if x[d] == server ]

        for row in temp:
            protoCnt[ row[PROTO] ] += 1
        proto, _ = protoCnt.most_common(1)[0]   # proto is the protocol used by server
        temp_result = [ x for x in relevantLog if x[d] == server and x[PROTO] == proto ]
        result.append( temp_result )

    return result


def analyze( log: List[str], output ) -> None:
    # calculate average size of packets
    lengths = [ int( x[LENGTH] ) for x in log ]
    mean = np.mean( lengths )
    median = np.median( lengths )
    output.write( '\t' + 'mean size: ' + str( mean ) + '\n' +
                  '\t' + 'median size: ' + str( median ) + '\n' )

    # calculate average time diff between each packet
    times = [ float( x[TIME] ) for x in log ]
    deltas = [ t - s for s, t in zip( times, times[1:] ) ]
    mean = np.mean(deltas)
    median = np.median(deltas)
    output.write( '\t' + 'mean delta: ' + str( mean ) + '\n' +
                  '\t' + 'median delta: ' + str( median ) + '\n' )




if __name__== "__main__":
    main()
