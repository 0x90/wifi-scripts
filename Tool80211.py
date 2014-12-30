#!/usr/bin/env python
import threading
import time
import sys
import os
import fcntl
import struct
from select import select
import pcap
# custom imports
import Parse80211
import PyLorcon2
from wifiobjects import *

#debug imports
import pdb
import sys

class iface80211:
    """
    handle 80211 interfacs
    """
    def __init__(self):
        self.TUNSETIFF = 0x400454ca
        self.TUNSETOWNER = self.TUNSETIFF + 2
        self.IFF_TUN = 0x0001
        self.IFF_TAP = 0x0002
        self.IFF_NO_PI = 0x1000


    def checkTun(self, path):
        """
        check for tuntap support
        """
        # doesnt work
        #return os.path.isfile(path)
        return True

    def openTun(self):
        """
        open up a tuntap interface
        path is /dev/net/tun in TAP (ether) mode
        returns false if failed
        """
        path = "/dev/net/tun"
        if self.checkTun(path) is not False:
            self.tun = os.open(path, os.O_RDWR)
            # ifr = struct.pack("16sH", "tun%d", self.IFF_TAP | self.IFF_NO_PI)
            ifr = struct.pack("16sH", "tun%d", self.IFF_TAP)
            ifs = fcntl.ioctl(self.tun, self.TUNSETIFF, ifr)
            #fcntl.ioctl(self.tun, self.TUNSETOWNER, 1000)
            # return interface name
            ifname = ifs[:16].strip("\x00")
            # commented out...  for now!
            print "Interface %s created. Configure it and use it" % ifname
            # put interface up
            os.system("ifconfig %s up" %(ifname))
            # return interface name
            try:
                self.lp = pcap.pcapObject()
                self.lp.open_live(ifname, 1526, 0 ,100)
            except AttributeError:
                print "You have the wrong pypcap installed"
                print "Use https://github.com/signed0/pylibpcap.git"
            return ifname
        else:
            return False
    
    def inject(self, packet):
        """
        send bytes to pylorcon interface
        """
        if self.moniface is not None:
            self.moniface['ctx'].send_bytes(packet)

    
    def readTun(self):
        """
        read a packet from tun interface
        """
        packet = select([self.tun],[],[])[0]
        if self.tun in packet:
            return os.read(self.tun, 1526)
    
    def sniffTun(self):
        """
        read a packet from tun interface
        """
        return self.lp.next()

    def writeTun(self, packet):
        """
        write a packet to tun interface
        """
        os.write(self.tun, packet)

    def openMon(self, interface):
        """
        open a monitor mode interface and create a vap
        interface = string 
        currently assumes all cards are to be opened in monitor mode
        """
        # open the card up and gain a a context to them
        # create a dict with interface name and context
        try:
            self.moniface = {"ctx":PyLorcon2.Context(interface)}
        except PyLorcon2.Lorcon2Exception,e:
            print "%s is the %s interface there?" %(e, interface)
            sys.exit(-1)
        # place cards in injection/monitor mode
        self.moniface["ctx"].open_injmon()
        self.moniface["name"] = self.moniface["ctx"].get_vap()
        #self.air = self.Airview(self.moniface)
        #self.air.start()

    def getMonmode(self):
        """
        retruns mon interface object
        """
        return self.moniface

    def exit(self):
        """
        Close card context
        """
        self.moniface["ctx"].close()

class ChannelHop(threading.Thread):
    """
    Control a card and cause it to hop channels
    Only one card per instance
    """
    def __init__(self,interface):
        """
        set the channel hopping sequence
        expects lorcon injmon() context
        """
        self.lock = 0
        threading.Thread.__init__(self)
        threading.Thread.daemon = True
        self.iface = interface
        self.pause = False
        # dwell for 3 time slices on 1 6 11
        # default is 3/10 of a second
        # got the lists from kismet config file
        # thanks dragorn!
        self.channellist = [1,6,11,14,2,7,3,8,4,9,5,10,
            36,40,44,48,52,56,60,64,149,153,157,161,165]
        self.hopList = []
        self.current = 0
        self.checkChannels()

    def checkChannels(self):
        """
        card drivesr suck, determine what channels 
        a card supports before we start hopping
        """
        # try setting 802.11ab channels first
        # this may not work depending on 5ghz dfs
        # reverse so we start with 5ghz channels first
        for ch in self.channellist:
            try:
                self.iface.set_channel(ch)
            except PyLorcon2.Lorcon2Exception:
                continue
            self.hopList.append(ch)
    
    def pause(self):
        """
        Pause the channel hopping
        """
        self.pause = True

    def unpause(self):
        """
        Unpause the channel hopping
        """
        self.pause = False
    
    def setchannel(self, channel):
        """
        Set a single channel
        expects channel to be an int
        returns -1 if channel isnt supported
        #should raise an exception if this is the case
        """
        while self.lock == 1:
            print "!!!!!!!!!!!!!!Waiting for lock...!!!!!!!!!!!!"
            time.sleep(2)
        if channel in self.hopList:
            self.iface.set_channel(channel)
            return 0
        else:
            return -1

    def hop(self, dwell=.4):
        """
        Hop channels
        """
        while True:
            # hopping is paused though loop still runs
            if self.pause == True | self.lock == 1:
                continue
            for ch in self.hopList:
                try:
                    self.iface.set_channel(ch)
                except PyLorcon2.Lorcon2Exception:
                    continue
                self.current = ch
                if ch in [1,6,11]:
                    # dwell for 4/10 of a second
                    # we want to sit on 1 6 and 11 a bit longer
                    time.sleep(dwell)
                else:
                    time.sleep(.2)
    
    def run(self):
        """
        start the channel hopper
        """
        self.hop()

class Airview(threading.Thread):
    """
    Grab a snapshot of the air
    whos connected to who
    whats looking for what
    # note right now expecting to deal with only one card
    # will need to refactor code to deal with more then one in the future
    # dong this for time right now
    """
    def __init__(self, interface, mon=False):
        """
        Open up a packet parser for a given interface and create monitor mode interface
        Thread the instance
        interface = interface as string
        if mon = True then interface = to the dicitionary object from iface80211
        """
        self.stop = False
        self.hopper = ""
        threading.Thread.__init__(self)
        threading.Thread.daemon = True
        #create monitor mode interface
        if mon is False:
            self.intf = iface80211()
            self.intf.openMon(interface)
            monif = self.intf.getMonmode()
        else:
            monif = interface
        # get interface name for use with pylibpcap
        self.iface = monif["name"]
        # get context for dealing with channel hopper
        self.ctx = monif["ctx"]
        # open up a parser
        self.rd = Parse80211.Parse80211(self.iface)
        
        #### New code ####
        # dict object to store client objects in 
        # format is {mac_address:object}
        self.clientObjects = {}
        # dict object to store ap objects in
        # format is {bssid:object}
        self.apObjects = {}
        #dict object to store ess objects
        # format is {essid:object}
        self.essObjects = {}


    @staticmethod
    def pformatMac(hexbytes):
        """
        Take in hex bytes and pretty format them 
        to the screen in the xx:xx:xx:xx:xx:xx format
        """
        mac = []
        for byte in hexbytes:
            mac.append(byte.encode('hex'))
        return ':'.join(mac)

    def processData(self, frame):
        """
        Update self.clients var based on ds bits
        """
        bssid = frame["bssid"]
        src = frame["src"]
        dst = frame["dst"]
        ds = frame["ds"]
        assoicated = False
        wired = None
        # actual client mac
        clientmac = None
        # NOTE need to figure how to mark a client
        # no longer assoicated
        if ds == 0:
            # broadcast/adhoc
            assoicated = True
            wired = False
            clientmac = src

        elif ds == 1:
            # station to ap
            assoicated = True
            wired = False
            clientmac = src
        
        elif ds == 2:
            # ap to station
            clientmac = dst
            assoicated = True
            # check for wired broadcasts
            if self.rd.isBcast(dst) is True:
                # were working with a wired broadcast
                wired = True
                # reset client mac to correct src addr
                clientmac = src
            else:
                wired = False
        elif ds == 3:
            # wds, were ignoring this for now
            return
        client_obj = None
        # create client mac if it doesnt exist
        if clientmac not in self.clientObjects.keys(): 
            self.clientObjects[clientmac] = client(clientmac)
        client_obj = self.clientObjects[clientmac]
        client_obj.wired = wired
        client_obj.assoicated = assoicated
        if assoicated is True:
            client_obj.bssid = bssid
        #update last time seen
        client_obj.lts = time.time()
        #update access points with connected clients
        if bssid not in self.apObjects.keys():
            # create new object
            self.apObjects[bssid] = accessPoint(bssid)
        ###NOTE right now a client can show up connected to more the one AP
        # create ap objects based on bssids seen from clients
        # make sure we dont do broadcast addresses
        if self.rd.isBcast(bssid) is False:
            if bssid not in self.apObjects.keys():
                # create new object
                self.apObjects[bssid] = accessPoint(bssid)
            # update list of clients connected to an AP
            ap_object = self.apObjects[bssid]
            ap_object.connectedclients.append(clientmac)

    def parse(self):
        """
        Grab a packet, call the parser then update
        The airview state vars
        """
        while self.stop is False:
            #TODO: we may need to set semaphore here?
            self.hopper.lock = 1
            self.channel = self.hopper.current
            frame = self.rd.parseFrame(
                        self.rd.getFrame())
            
            # not sure if this is needed any more
            self.hopper.lock = 0
            #release semaphore here -- we have what we came for
            
            # beacon frames
            if frame == None:
                # we cant parse the frame
                continue
            if frame == -1:
                # frame is mangled
                continue
            
            if frame["type"] == 0 and frame["stype"] == 8:
                # beacon packet
                ap_object = None
                bssid = frame["bssid"]
                essid = frame["essid"]
                # grab the AP object or create it if it doesnt exist
                if bssid not in self.apObjects.keys():
                    # create new object
                    self.apObjects[bssid] = accessPoint(bssid)
                ap_object = self.apObjects[bssid]
                # update essid
                ap_object.updateEssid(essid)
                # update ap_last time seen
                ap_object.lts = time.time()
                # update the ess
                #NOTE this is broken, need to populate ess from ap's
                if ap_object.essid in self.essObjects.keys():
                    if bssid not in self.essObjects[essid].points:
                        self.essObjects[essid].points.append(bssid)
                #need to update other ap features
            
            elif frame["type"] == 2 and frame["stype"] in range(0,16):
                #applying to all data packets
                self.processData(frame)
            
            if frame["type"] == 0 and frame["stype"] in [4]:
                # probes parsing
                # update client list
                self.processData(frame)
                # process probe for essid
                src = frame["src"]
                essid = frame["essid"]
                if src not in self.clientObjects.keys(): 
                    self.clientObjects[clientmac] = client(src)
                client_obj = self.clientObjects[src]
                client_obj.updateProbes(essid)
                client_obj.lts = time.time()

    def run(self):
        """
        start the parser
        """
        # need to start channel hopping here
        self.hopper = ChannelHop(self.ctx)
        self.hopper.start()
        self.parse()
    
    def kill(self):
        """
        stop the parser
        """
        self.stop = True
        self.intf.exit()

