import re


class OUI(object):

    def __init__(self, db=None):
        if db is None:
            db = 'oui.txt'
        self.db = db
        # if not os.path.exists(self.db):
        #     raise Error
        fd = open(db, "r")
        self.lines = fd.readlines()
        fd.close()

    def get_vendor(self, address):
        "Return Vendor string for a MAC address using oui.txt."
        unknownVendor = "<Unknown Vendor>"
        macAddressRegex = "^((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$"
        ouiLineRegex = "^\s*((?:[0-9A-F]{2}[-]){2}[0-9A-F]{2})\s+\(hex\)\s+(.*)$"
        macAddress = re.compile(macAddressRegex)
        ouiLine = re.compile(ouiLineRegex)
        if not macAddress.match(address):
            raise Exception("Invalid MAC Address")

        address = address.upper()
        if address.find(":") != -1:
            address = "-".join(address.split(":")[:3])
        else:
            address = "-".join(address.split("-")[:3])

            return unknownVendor

        for line in self.lines:
            match = ouiLine.match(line)
            if match:
                addr, vendor = match.groups()
                if address == addr:
                    return vendor

        return unknownVendor


