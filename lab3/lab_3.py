LOG_FILE = "setupapi.dev.log"
DEVICE_USB_STR = "USBSTOR"
DEVICE_START_STR = "[Device Install (Hardware initiated)"


def printDevices(devices, timestamp):
    print("*" * 20)
    print("VendorID: ", devices[1][1])
    print("ProductID: ", devices[1][2])
    print("Revision: ", devices[1][3])
    print("Serial Number: ", devices[0])
    print("-" * 20)
    print("Timestamp: ", timestamp[0], timestamp[1])
    print("*" * 20)


devices = []

with open(LOG_FILE) as f:
    for line in f:
        if DEVICE_START_STR in line and DEVICE_USB_STR in line:
            timestamp = next(f).split()[3:]
            devices = line.split("#")[1:3]
            devices.append(devices[0].split("&"))
            devices = devices[1:]
            printDevices(devices, timestamp)
