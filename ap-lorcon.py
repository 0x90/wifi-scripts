import sys
import random
from time import sleep
import PyLorcon2

from impacket import dot11
from impacket.dot11 import Dot11
from impacket.dot11 import Dot11Types
from impacket.dot11 import Dot11ManagementFrame
from impacket.dot11 import Dot11ManagementBeacon

def getBeacon(src, ssid):
  "Return 802.11 Beacon Frame."

  # Frame Control
  frameCtrl = Dot11(FCS_at_end = False)
  frameCtrl.set_version(0)
  frameCtrl.set_type_n_subtype(Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_BEACON)
  # Frame Control Flags
  frameCtrl.set_fromDS(0)
  frameCtrl.set_toDS(0)
  frameCtrl.set_moreFrag(0)
  frameCtrl.set_retry(0)
  frameCtrl.set_powerManagement(0)
  frameCtrl.set_moreData(0)
  frameCtrl.set_protectedFrame(0)
  frameCtrl.set_order(0)

  # Management Frame
  sequence = random.randint(0, 4096)
  broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
  mngtFrame = Dot11ManagementFrame()
  mngtFrame.set_duration(0)
  mngtFrame.set_destination_address(broadcast)
  mngtFrame.set_source_address(src)
  mngtFrame.set_bssid(broadcast)
  mngtFrame.set_fragment_number(0)
  mngtFrame.set_sequence_number(sequence)

  # Beacon Frame
  baconFrame = Dot11ManagementBeacon()
  baconFrame.set_ssid(ssid)
  baconFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x48])
  baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x12\x24\x60\x6c")

  mngtFrame.contains(baconFrame)
  frameCtrl.contains(mngtFrame)

  return frameCtrl.get_packet()

if __name__ == "__main__":
  if len(sys.argv) != 3:
    print "Usage"
    print "  %s  <iface> <essid>" % sys.argv[0]
    sys.exit()

  iface = sys.argv[1]
  essid = sys.argv[2]

  context = PyLorcon2.Context(iface)
  context.open_injmon()
  moniface = context.get_capiface()

  src = [0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
  beacon = getBeacon(src, essid)

  if essid == "":
    essid = "broadcast"

  print "Using interface %s" % iface
  print "Creating fake AP with name '%s'." % essid

  while True:
    context.send_bytes(beacon)
    sleep(0.1)