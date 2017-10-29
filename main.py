#!/usr/bin/env python3

import sys
import os
import csv
import re
from collections import Counter
from typing import Dict, List, Tuple
import numpy as np
import matplotlib.pyplot as plt

UPLOAD = 'upload'
DOWNLOAD = 'download'

NEGLIGIBLE_THRESHOLD = 10  # if a server sends < N packets during a period, ignore it
SERVER_LIMIT = 3  # analyze communication between localIP and up to N different servers

NO = 0
TIME = 1
SRC = 2
DST = 3
PROTO = 4
LENGTH = 5
INFO = 6

script_dir = os.path.dirname(__file__)
diagram_dir = os.path.join(script_dir, 'Diagrams/')

if not os.path.isdir(diagram_dir):
    os.makedirs(diagram_dir)

def main():
    """
    args: logfile.csv argFile.csv ip_address
    idxFile should have 3 args in each row, i.e.

    idxStart1 idxEnd1 name1
    idxStart2 idxEnd2 name2

    all indices are inclusive
    """
    args = sys.argv
    assert (len(args) == 4)
    logName = args[1]
    idxName = args[2]
    localIP = args[3]

    regex = '([\d]+) ([\d]+) (.*)'

    with open(logName, 'rt', encoding='utf-8') as log, \
            open(idxName, 'rt', encoding='utf-8') as idx, \
            open('result.txt', 'w') as output:
        idxLst = []
        for row in idx:
            result = re.match(regex, row)
            assert (result is not None)
            t = result.groups()
            assert (len(t) == 3 and int(t[0]) < int(t[1]))
            idxLst.append((int(t[0]), int(t[1]), t[2]))

        logReader = csv.reader(log)
        lines = list(logReader)
        print (len(lines))
        for t in idxLst:
            print (t[0], t[1])
            assert (0 < t[0] < len(lines) and 0 < t[1] < len(lines))

        # analyze period, return a list of logs clustered by servers
        for t in idxLst:
            output.write("\nANALYZE %s(%d ~ %d) PERIOD(DOWNLOAD)\n" % (t[2], t[0], t[1]))
            analyzeThroughput(lines, t[0], t[1], localIP, DOWNLOAD, output)
            activeDownLogList = preprocess(lines, localIP, t[0], t[1], DOWNLOAD)
            for log in activeDownLogList:
                output.write('%s ---> %s (%s) [%d packets]:\n' % (log[0][SRC], localIP, log[0][PROTO], len(log)))
                #analyze(log, output, log[0][SRC], DOWNLOAD, t[2], plot=True)

            output.write("\nANALYZE %s(%d ~ %d) PERIOD(UPLOAD)\n" % (t[2], t[0], t[1]))
            analyzeThroughput(lines, t[0], t[1], localIP, UPLOAD, output)
            activeUpLogList = preprocess(lines, localIP, t[0], t[1], UPLOAD)
            for log in activeUpLogList:
                output.write('%s ---> %s (%s) [%d packets]:\n' % (log[0][DST], localIP, log[0][PROTO], len(log)))
                #analyze(log, output, log[0][DST], UPLOAD, t[2], plot=True)


def analyzeThroughput(log: List[List[str]], start:int, end:int, localIp:str, dir: str, output) -> None:
    # calculate the average throughput
    d = SRC if dir == UPLOAD else DST
    #print(log[start:end+1])
    timePassed = float(log[end][TIME]) - float(log[start][TIME])

    sizes = [float(x[LENGTH]) / float(timePassed) for x in log[start:end+1] if x[d] == localIp]

    mean = np.sum(sizes)
    output.write('\t' + 'mean throughput: %.2f\n' % mean)




def preprocess(lines: List[List[str]],
               localIP: str, start: int, end: int, dir: str) -> List[List[List[str]]]:
    """filter log entries that:
    1) has NO. between [start, end]
    2) has correct stream direction
    3) pick only top SERVER_LIMIT server IPs with the most common protocol
    4) is not TCP ACK(Len != 0)
    """
    d = DST if dir == UPLOAD else SRC  # if we are uploading, pick top SERVER_LIMIT from DST, else SRC

    # filter by direction, and non-emptiness
    serverCnt = Counter()
    if dir == UPLOAD:
        relevantLog = list(filter(lambda x: x[SRC] == localIP, lines[start:end + 1]))
    else:  # DOWNLOAD
        relevantLog = list(filter(lambda x: x[DST] == localIP, lines[start:end + 1]))

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


def analyze(log: List[List[str]], output, server: str, dir: str, desc: str, plot=True) -> None:
    """Add your own analyzer function here"""
    analyzePort(log, output, server, dir)
    analyzeLength(log, output, server, dir, desc)
    analyzeLength(log, output, server, dir, desc, plot)
    analyzeTime(log, output, server, dir, desc, plot)


def analyzeLength(log: List[List[str]], output, server: str, dir: str, desc: str, plot=False) -> None:
    # calculate average size of packets
    log = list(filter(lambda x: 'Len=0' not in x[INFO], log))
    proto = log[0][PROTO]
    lengths = [int(x[LENGTH]) for x in log]
    mean = np.mean(lengths)
    median = np.median(lengths)
    variance = np.var(lengths)
    output.write('\t' + 'mean size: ' + '%.2f' % mean + ' Bytes\n' +
                 '\t' + 'median size: ' + '%.2f' % median + ' Bytes\n' +
                 '\t' + 'variance: ' + '%.2f' % variance + ' Bytes\n')
    if plot:
        times = [float(x[TIME]) for x in log]
        plt.plot(times, lengths, marker='x', linestyle='--')
        plt.xlabel('time(s)')
        plt.ylabel('packet size(B)')
        plt.title('%s %s %s packet size analysis(%s)' % (desc, server, dir, proto))
        plt.savefig(diagram_dir + '%s_%s_%s_packet_size(%s).png' % (desc, server, dir, proto))
        plt.clf()


def analyzeTime(log: List[List[str]], output, server: str, dir: str, desc: str, plot=False) -> None:
    # calculate average time diff between each packet
    log = list(filter(lambda x: 'Len=0' not in x[INFO], log))
    proto = log[0][PROTO]
    times = [float(x[TIME]) for x in log]
    deltas = [(t - s) * 1000 for s, t in zip(times, times[1:])]
    mean = np.mean(deltas)
    median = np.median(deltas)
    variance = np.var(deltas)
    output.write('\t' + 'mean delta: ' + '%.2f' % mean + ' ms\n' +
                 '\t' + 'median delta: ' + '%.2f' % median + ' ms\n' +
                 '\t' + 'variance: ' + '%.2f' % variance + ' ms\n')
    if plot:
        times = [float(x[TIME]) for x in log]
        plt.plot(times[1:], deltas, marker='x', linestyle='--')
        plt.xlabel('time(s)')
        plt.ylabel('time diff(ms)')
        plt.title('%s %s %s time diff analysis(%s)' % (desc, server, dir, proto))
        plt.savefig(diagram_dir + '%s_%s_%s_time_diff(%s).png' % (desc, server, dir, proto))
        plt.clf()


def analyzePort(log: List[List[str]], output, server: str, dir: str) -> None:
    # analyze srcPort and dstPort
    log = list(filter(lambda x: 'Len=0' not in x[INFO], log))
    portCnt = Counter()
    for row in log:
        srcPort, dstPort = portNum(row)
        if srcPort is None:
            continue
        k = 'srcPort: ' + srcPort + ' > ' + 'dstPort: ' + dstPort
        portCnt[k] += 1
    for m, cnt in portCnt.most_common():
        output.write('\t' + m + ': ' + str(cnt) + ' packets\n')


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
