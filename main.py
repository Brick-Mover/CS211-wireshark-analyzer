#!/usr/bin/python

import sys
import csv
from collections import Counter
from typing import Dict, List
import numpy as np
import matplotlib.pyplot as plt

UPLOAD = 0
DOWNLOAD = 1

NEGLIGIBLE_THRESHOLD = 10  # if a server sends < N packets during a period, ignore it
SERVER_LIMIT = 3  # analyze communication between localIP and up to N different servers

NO = 0
TIME = 1
SRC = 2
DST = 3
PROTO = 4
LENGTH = 5
INFO = 6


def main():
    """
    args: logfile.csv active_start_idx, active_end_idx, idle_start_idx, idle_end_idx, ip_address
    all indices are inclusive
    """
    args = sys.argv
    assert (len(args) == 7)
    filename = args[1]  # this is the name of the log, in CSV format
    activeStart = int(args[2])
    activeEnd = int(args[3])
    idleStart = int(args[4])
    idleEnd = int(args[5])
    localIP = args[6]

    with open(filename, 'rt', encoding='utf-8') as log, open('result.txt', 'w') as output:
        logReader = csv.reader(log)
        lines = list(logReader)
        assert (0 < int(x) < len(lines) for x in args[2:6])

        # analyze ACTIVE period, return a list of logs clustered by servers
        output.write("ANALYZE ACTIVE PERIOD\n")
        output.write("ACTIVE: DOWNLOAD\n")
        activeDownLogList = preprocess(lines, localIP, activeStart, activeEnd, DOWNLOAD)
        for log in activeDownLogList:
            output.write('%s ---> %s (%s) [%d packets]:\n' % (log[0][SRC], localIP, log[0][PROTO], len(log)))
            analyze(log, output, log[0][SRC], DOWNLOAD)

        output.write("\nACTIVE: UPLOAD\n")
        activeUpLogList = preprocess(lines, localIP, activeStart, activeEnd, UPLOAD)
        for log in activeUpLogList:
            output.write('%s ---> %s (%s) [%d packets]:\n' % (log[0][DST], localIP, log[0][PROTO], len(log)))
            analyze(log, output, log[0][DST], UPLOAD)

        # analyze IDLE period, return a list of logs clustered by servers
        output.write("\nANALYZE IDLE PERIOD\n")
        output.write("IDLE: DOWNLOAD\n")
        idleDownLogList = preprocess(lines, localIP, idleStart, idleEnd, DOWNLOAD)
        for log in idleDownLogList:
            output.write('%s ---> %s (%s) [%d packets]:\n' % (log[0][SRC], localIP, log[0][PROTO], len(log)))
            analyze(log, output, log[0][SRC], DOWNLOAD)

        output.write("\nIDLE: UPLOAD\n")
        idleUpLogList = preprocess(lines, localIP, idleStart, idleEnd, UPLOAD)
        for log in idleUpLogList:
            output.write('%s ---> %s (%s) [%d packets]:\n' % (log[0][DST], localIP, log[0][PROTO], len(log)))
            analyze(log, output, log[0][DST], UPLOAD)


def preprocess(lines: List[List[str]],
               localIP: str, start: int, end: int, dir: int) -> List[List[List[str]]]:
    """filter log entries that:
    1) has NO. between [start, end]
    2) has correct stream direction
    3) pick only top SERVER_LIMIT server IPs with the most common protocol
    4) us not TCP ACK(Len != 0)
    """
    d = DST if dir == UPLOAD else SRC  # if we are uploading, pick top SERVER_LIMIT from DST, else SRC

    # filter by direction, and non-emptiness
    serverCnt = Counter()
    if dir == UPLOAD:
        relevantLog = list(filter(lambda x: x[SRC] == localIP and 'Len=0' not in x[INFO],
                                  lines[start:end + 1]))
    else:  # DOWNLOAD
        relevantLog = list(filter(lambda x: x[DST] == localIP and 'Len=0' not in x[INFO],
                                  lines[start:end + 1]))

    # pick top SERVER_LIMIT servers
    for row in relevantLog:
        serverCnt[row[d]] += 1
    servers = serverCnt.most_common(SERVER_LIMIT)

    # filter by the most common protocol for each server
    result = []
    protoCnt = Counter()
    for (server, _) in servers:
        temp = [x for x in relevantLog if x[d] == server]

        for row in temp:
            protoCnt[row[PROTO]] += 1
        proto, _ = protoCnt.most_common(1)[0]  # proto is the most common protocol used by server
        temp_result = [x for x in relevantLog if x[d] == server and x[PROTO] == proto]
        # ignore if a server sends too few packets using proto
        if len(temp_result) >= NEGLIGIBLE_THRESHOLD:
            result.append(temp_result)

    return result


def analyze(log: List[List[str]], output, server: str, dir: int) -> None:
    """Add your own analyzer function here"""
    analyzePort(log, output, server, dir)
    analyzeLength(log, output, server, dir, plot=True)
    analyzeTime(log, output, server, dir, plot=True)


def analyzeLength(log: List[List[str]], output, server: str, dir: int, plot=False) -> None:
    # calculate average size of packets
    lengths = [int(x[LENGTH]) for x in log]
    mean = np.mean(lengths)
    median = np.median(lengths)
    output.write('\t' + 'mean size: ' + str(mean) + '\n' +
                 '\t' + 'median size: ' + str(median) + '\n')

    if plot:
        times = [float(x[TIME]) for x in log]
        plt.plot(times, lengths, marker='x', linestyle='--')
        plt.xlabel('time(s)')
        plt.ylabel('packet size(B)')
        title = 'upload to %s' if dir == UPLOAD else 'download from %s'
        plt.title(title % server)
        plt.savefig(server + '_upload_length.png' if dir == UPLOAD else server + '_download_length.png')
        plt.clf()


def analyzeTime(log: List[List[str]], output, server: str, dir: int, plot=False) -> None:
    # calculate average time diff between each packet
    times = [float(x[TIME]) for x in log]
    deltas = [(t - s) * 1000 for s, t in zip(times, times[1:])]
    mean = np.mean(deltas)
    median = np.median(deltas)
    output.write('\t' + 'mean delta: ' + str(mean) + '\n' +
                 '\t' + 'median delta: ' + str(median) + '\n')

    if plot:
        times = [float(x[TIME]) for x in log]
        plt.plot(times[1:], deltas, marker='x', linestyle='--')
        plt.xlabel('time(s)')
        plt.ylabel('time diff(ms)')
        title = 'upload to %s' if dir == UPLOAD else 'download from %s'
        plt.title(title % server)
        plt.savefig(server + '_upload_timediff.png' if dir == UPLOAD else server + '_download_timediff.png')
        plt.clf()


def analyzePort(log: List[List[str]], output, server: str, dir: int) -> None:
    # analyze srcPort and dstPort
    portCnt = Counter()
    for row in log:
        srcPort, dstPort = portNum(row)
        if srcPort is None:
            continue
        k = srcPort + ' > ' + dstPort
        portCnt[k] += 1
    for m, cnt in portCnt.most_common():
        output.write('\t' + m + ': ' + str(cnt) + ' packets.\n')


def portNum(row: List[str]) -> (str, str):
    """Parse port number from INFO section, return ( srcPort, dstPort )"""
    idx = row[INFO].find('>')
    if idx == -1:
        return None, None
    b = idx - 3
    while b >= 0 and row[INFO][b].isdigit():
        b -= 1
    srcPort = row[INFO][b + 1:idx - 2]
    f = idx + 3
    while f < len(row[INFO]) and row[INFO][f].isdigit():
        f += 1
    dstPort = row[INFO][idx + 3:f]
    return srcPort, dstPort


if __name__ == "__main__":
    main()
