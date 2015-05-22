#!/usr/bin/env python2
# Based on http://midnightresearch.com/local/hackery/wifi-theremin.py
#
# Create a pseudo-theremin from your wifi device 
#
# The frequency of the tone is inversely proportional to the signal strength of the AP
# that you are connected to.  If specified, the Volume is proportional to the
# signal strength of the second card. You must be associated to an AP for it to
# work.
#
# Requires pyaudio (which requires portaudio) apt-get install libportaudio2 python-support 
# wget http://people.csail.mit.edu/hubert/pyaudio/packages/python-pyaudio_0.2.3_i386.deb
# See here for details: http://people.csail.mit.edu/hubert/pyaudio/
#
# Works on linux and OSX, tested on Kali Linux 1.0.8, and Max OS X 10.9.5 respectively
#
# Aaron Peterson -- aaron@midnightresearch.com
# @090h http://twitter.com/090h
#
# Requerements:
#   apt-get install libportaudio2
#   apt-get install python-pyaudio
#

from sys import exit, platform, argv
from threading import Thread, Event
from os import popen, path
from math import pi, sin
from signal import signal, SIGINT
from struct import pack
from random import randrange
from time import sleep, time


try:
    import pyaudio
except ImportError:
    print(" [!] Need pyaudio from http://people.csail.mit.edu/hubert/pyaudio/")
    print("     'easy_install pyaudio' may work, but it also depends on PortAudio")
    exit(1)


class Tone(Thread):
    """ This module just emits a tone based on the frequency/volume that it's set to"""

    def __init__(self, id=None, freq=1000):
        Thread.__init__(self)
        self.id = id
        self.freq = freq
        self.stop = Event()

        # ####################################################
        # Constants that come from the pyAudio sample scripts
        # Short int audio format
        self.WIDTH = 2
        self.CHANNELS = 2
        self.RATE = 44100
        # Signed short range
        self.maxVolume = 10000
        ######################################################

        self.volume = 10000
        signal(SIGINT, self.sigHandler)
        self.p = pyaudio.PyAudio()
        self.stream = self.p.open(format=self.p.get_format_from_width(self.WIDTH),
                                  channels=self.CHANNELS,
                                  rate=self.RATE,
                                  output=True)

    def run(self):
        print " [*] Starting up toner"
        self.doTone()

    def doTone(self):
        i = 0
        while True:
            i += 1
            # Taken from pyaudio sample scripts
            phase = i * 2 * pi * self.freq / self.RATE
            # compute sin value
            sample = self.volume * sin(phase)
            # convert to short int
            data = pack('h', sample)
            for c in range(self.CHANNELS):
                # write one sample to each channel
                self.stream.write(data, 1)

    def cleanUp(self):
        print(" [*] Stopping toner...")
        self.stream.stop_stream()
        self.stream.close()
        self.p.terminate()
        print(" [*] Toner Done.")
        exit(1)

    def sigHandler(self, signum, stackframe):
        self.cleanUp()


class WifiTheremin():
    def __init__(self, pitchDevice=None, volumeDevice=None, toner=None):
        # The range of frequencies we'll use
        self.lowFreq = 300
        self.highFreq = 8000
        # The range of signal values (for pitch), they will expand as higher/lower values are seen
        self.lowPitchSignal = None
        self.highPitchSignal = None
        # The range of signal values for volume
        self.lowVolumeSignal = None
        self.highVolumeSignal = None
        self.pitchDevice = pitchDevice
        self.volumeDevice = volumeDevice
        self.toner = toner

        # To smooth things out we'll sample and interpolate the sound results over some
        # period.  Would sound better if we did something more inteligent, but this
        # will do for now.
        self.interpolateCycle = 0.5
        # How much to sleep between freq changes... it gets too noisy if it's too
        # short, but to choppy if it's too long.  But baby bear's porridge is *just* right.
        self.sleepCycle = 0.03

    def getSignal(self, device):
        """Gets the signal strength of the selected wifi intereface."""
        signal = 0
        # In theory we could just replace the get*Signal function to support other systems
        if device == "test":
            # This is just for testing the sound device, etc.
            signal = self.getFakeSignal()
        elif platform == "darwin":
            signal = self.getOsxSignal(device)
        elif platform == "linux2":
            signal = self.getLinuxSignal(device)
        else:
            print(" [!] Unsupported platform [%s]" % platform)
            exit(1)

        if signal == "":
            print(" [!] Not getting a valid signal for [%s], you might need to associate to an AP..." % device)
            exit(1)

        print " [*] Signal strength [%s] [%s]" % (signal, device)
        return signal

    def getOsxSignal(self, device):
        """Gets signal strength for wifi under OSX"""
        # Let me know if you know a better way to get this information...
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        cmd = "%s -I | grep agrCtlRSSI | awk '{ print $2 }'" % airport
        try:
            return popen(cmd, "r").readline().rstrip()
        except IOError:
            print " [!] Problem executing [%s] to get signal" % cmd
            print "     You should be connected to an access point to get signal strength"
            exit(1)


    def getLinuxSignal(self, device):
        """Gets signal strength for wifi under Linux"""
        if path.exists('/sbin/iw'):
            cmd = "iwlist %s scan | grep 'Signal level'" % device
        else:
            cmd = "iwconfig %s | grep 'Signal level'" % device

        try:
            return popen(cmd, "r").readline().split('=')[-1].split(' ')[0].rstrip()
        except:
            print(" [!] Problem running [%s] to get signal" % cmd)
            print("     You should be connected to an access point to get signal strength")
            exit(1)

    def getFrequency(self):
        """This will get the frequency based on the current signal strength and
		the range of observed signal ranges.  It doesn't handle any ramp up.
		The Higher the signal strength, the lower the pitch"""
        signal = float(self.getSignal(self.pitchDevice))
        freq = self.lowFreq
        # Adjust the min/max ranges
        if not self.lowPitchSignal or signal < self.lowPitchSignal: self.lowPitchSignal = signal
        if not self.highPitchSignal or signal > self.highPitchSignal: self.highPitchSignal = signal
        # Set the freq based on a ratio against the max ranges
        freqRange = self.highFreq - self.lowFreq
        signalRange = self.highPitchSignal - self.lowPitchSignal
        adjSignal = signal - self.lowPitchSignal
        if signalRange == 0 or adjSignal == 0: return self.lowFreq
        freq = self.lowFreq + ((1 - (adjSignal / signalRange)) * freqRange)
        return freq

    def getFakeSignal(self):
        """Fake signal for testing sound, etc."""
        return randrange(1, 100)

    def getVolume(self):
        """Return the absolute volume we want to be at based on the signal strength
		The higher the signal strength, the higher the volume"""
        signal = float(self.getSignal(self.volumeDevice))
        volume = self.toner.maxVolume
        # adjust the min/max ranges
        if not self.lowVolumeSignal or signal < self.lowVolumeSignal: self.lowVolumeSignal = signal
        if not self.highVolumeSignal or signal > self.highVolumeSignal: self.highVolumeSignal = signal
        # Some redundant code here, but oh well
        signalRange = self.highVolumeSignal - self.lowVolumeSignal
        adjSignal = signal - self.lowVolumeSignal
        if signalRange == 0 or adjSignal == 0: return self.toner.maxVolume
        volume = (adjSignal / signalRange) * self.toner.maxVolume
        return volume

    def run(self):
        print " [*] Starting up theremin"
        startFreq = self.lowFreq
        while True:
            nextFreq = self.getFrequency()
            cycleStartTime = time()
            if self.volumeDevice:
                self.toner.volume = self.getVolume()
            # Ramp up the frequency over the length of the cycle so the sound isn't too jumpy
            while time() - cycleStartTime < self.interpolateCycle:
                # Get the signal based on the interpolated values
                self.toner.freq = startFreq + (
                    ((time() - cycleStartTime) / self.interpolateCycle) * (nextFreq - startFreq))
                startFreq = self.toner.freq
                sleep(self.sleepCycle)


if __name__ == "__main__":
    if len(argv) < 2:
        print("")
        print(" usage: %s <wifi device (pitch)> [<wifi device (volume)>]" % argv[0])
        print("")
        print("        Note: Specifying 'test' as the wifi device (for pitch or volume) will")
        print("        test the sound with random ranges.  Volume device is not required.")
        print("")
        exit(1)

    # Devices
    pitchDevice = argv[1]
    volumeDevice = argv[2] if len(argv) == 3 else None

    tone = Tone(id=1)
    # Start new thread for toner
    tone.start()
    wt = WifiTheremin(pitchDevice=pitchDevice, volumeDevice=volumeDevice, toner=tone)
    wt.run()
    # Wait for thread to finish
    tone.join()
    print(" [*] Wifi Theremin Finished.")

