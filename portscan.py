
import threading, socket, sys, cmd, os, Queue

lock = threading.Lock()

def GetQueue(host):
    PortQueue = Queue.Queue()
    ports = [11211,27017]
    for port_list in range(1,10000):
        ports.append(port_list)
    for port in ports:
        PortQueue.put((host,port))
    return PortQueue

class ScanThread(threading.Thread):
    def __init__(self,SingleQueue,outip):
        threading.Thread.__init__(self)
        self.setDaemon(True)        
        self.SingleQueue = SingleQueue
        self.outip = outip

    def Ping(self,scanIP, Port):
        global OpenPort, lock
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        address = (scanIP, Port)
        try:
            sock.connect(address)
        except:
            sock.close()
            return False
        sock.close()
        if lock.acquire():
            print "[+] Get IP:%s  Port:%s open" % (scanIP, str(Port))
            self.outip.put(Port)
            lock.release()
        return True

    def run(self):
        while not self.SingleQueue.empty():
            host,port = self.SingleQueue.get()
            self.Ping(host,port)


class Work(object):
    def __init__(self,scan_target = ""):
        self.target = scan_target
        self.result = []
    def run(self):
        ThreadList = []
        SingleQueue = GetQueue(self.target)
        resultQueue = Queue.Queue()
        for i in range(0, 500):
            t = ScanThread(SingleQueue,resultQueue)
            ThreadList.append(t)
        for t in ThreadList:
            t.start()
        for t in ThreadList:
            t.join(0.1)
        data = []
        while not resultQueue.empty():
            line = resultQueue.get()
            data.append(line)
        return data

#t = Work(scan_target = "176.28.50.165")#43.242.128.230
#print t.run()