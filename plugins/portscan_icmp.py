#coding:utf-8

import threading,socket,struct,time,os,array,ssl
import traceback

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

class SendPingThr(threading.Thread):
    def __init__(self, ipPool, icmpPacket, icmpSocket, timeout=3):
        threading.Thread.__init__(self)
        self.Sock = icmpSocket
        self.ipPool = ipPool
        self.packet = icmpPacket
        self.timeout = timeout
        self.Sock.settimeout(timeout + 1)

    def run(self):
        time.sleep(0.01)
        for ip in self.ipPool:
            try:
                self.Sock.sendto(self.packet, (ip, 0))
            except socket.timeout:
                break
        time.sleep(self.timeout)

class Nscan:
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.__data = struct.pack('d', time.time())
        self.__id = os.getpid()

    @property
    def __icmpSocket(self):
        Sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        return Sock

    def __inCksum(self, packet):
        if len(packet) & 1:
            packet = packet + '\0'
        words = array.array('h', packet)
        sum = 0
        for word in words:
            sum += (word & 0xffff)
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        return (~sum) & 0xffff

    @property
    def __icmpPacket(self):
        header = struct.pack('bbHHh', 8, 0, 0, self.__id, 0)
        packet = header + self.__data
        chkSum = self.__inCksum(packet)
        header = struct.pack('bbHHh', 8, 0, chkSum, self.__id, 0)
        return header + self.__data

    def mPing(self, ipPool):
        Sock = self.__icmpSocket
        Sock.settimeout(self.timeout)
        packet = self.__icmpPacket
        recvFroms = set()
        sendThr = SendPingThr(ipPool, packet, Sock, self.timeout)
        sendThr.start()
        while True:
            try:
                ac_ip = Sock.recvfrom(1024)[1][0]
                if ac_ip not in recvFroms:
                    recvFroms.add(ac_ip)
            except Exception:
                pass
            finally:
                if not sendThr.isAlive():
                    break
        return recvFroms & ipPool

def get_ac_ip(ip_list):
    '''
    ICMP check alive
    '''
    try:
        s = Nscan()
        ipPool = set(ip_list)
        return s.mPing(ipPool)
    except Exception,e:
        print '[!] The current user permissions unable to send icmp packets'
        # print traceback.format_exc()
        return ip_list
