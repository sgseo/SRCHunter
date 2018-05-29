# -*- coding: utf-8 -*-
# Author:Bing
# Contact:amazing_bing@outlook.com


import threading, socket, sys, os, Queue
from lib.config import check_big_ports,big_ports

class ScannerThread(threading.Thread):
    def __init__(self, inq, outq):
        threading.Thread.__init__(self)
        # queues for (host, port)
        self.setDaemon(True)
        self.inq = inq
        self.outq = outq
        self.killed = False
        self.timeout = 0.5

    def run(self):
        while not self.killed:
            host, port = self.inq.get()
            sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sd.settimeout(self.timeout)
            try:
                # connect to the given host:port
                sd.connect((host, port))
                self.outq.put((host, port, 'OPENED'))
            except socket.error:
                # set the CLOSED flag
                self.outq.put((host, port, 'CLOSED'))             
            sd.close()


class Scanner:
    def __init__(self, from_port, to_port, host='localhost'):
        self.from_port = from_port
        self.to_port = to_port
        self.host = host
        self.scanners = []

    def scan(self, search_for='opened',first_match=False, nthreads=1,send_fn=None, exclude=[]):
        self.resp = []
        toscan = Queue.Queue()
        scanned = Queue.Queue()
        self.scanners = [ScannerThread(toscan, scanned) for i in range(nthreads)]
        for scanner in self.scanners:
            scanner.start()
        hostports = [(self.host, port) for port in xrange(self.from_port, self.to_port+1) if port not in exclude]
        if check_big_ports:
            hostports =  list(set(hostports + [(self.host, bport) for bport in big_ports]))
            hostports.sort()
        for hostport in hostports:
            toscan.put(hostport)

        results,open_ports = {},[]
        for host, port in hostports:
            while (host, port) not in results:
                nhost, nport, nstatus = scanned.get()
                results[(nhost, nport)] = nstatus
            status = results[(host, port)]
            value = (host, port, status)
            if status == 'OPENED' and search_for.lower() == 'opened':
                print '[+]',host, port, status
                open_ports.append(port)
                if send_fn:
                    send_fn(value)
                if first_match:
                    return self._finish_scan()
            elif status == 'CLOSED' and search_for.lower() == 'closed':
                if send_fn:
                    send_fn(value)
                if first_match:
                    return self._finish_scan()
            elif search_for.lower() == 'all':
                if send_fn:
                    send_fn(value)
                if first_match:
                    return self._finish_scan()
        return open_ports


    def _finish_scan(self):
        for scanner in self.scanners:
            scanner.join(0.001)
            scanner.killed = True
        return self.resp

# scanner = Scanner(from_port=1, to_port=100,host='176.28.50.165')
# print scanner.scan(search_for='opened',first_match=False, nthreads=50, send_fn='')
