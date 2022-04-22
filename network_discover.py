from subprocess import run
from scapy.all import Ether, ARP, srp
from termcolor import colored
from argparse import ArgumentParser
from socket import herror, gaierror, gethostbyaddr
from os.path import dirname
from sys import stdout
from os import chdir, name


def getArguments():

    myparse = ArgumentParser()
    myparse.add_argument(
        "--ipField", help="Enter a ip field. Ex: 192.168.1.0/24")
    myparse.add_argument("--outFile", help="Enter a file Ex: scanresults.txt")
    myparse.add_argument(
        "--getHostname", help="Do you want to know the hostname?  Ex: y or n")
    myparse.add_argument(
        "--interface", help="Enter the interface name to use (Ex: wlan0, 'Wi-Fi 2')")
    return myparse.parse_args()


def getHostName(ip):

    try:
        n = gethostbyaddr(ip)[0]
        n = "UNKNOWN" if (n == "") else n
        return n

    except (herror, gaierror):
        return "UNKNOWN"


def discover():

    arp_p = ARP(pdst=ipField, psrc="")
    ether_p = Ether(dst="ff:ff:ff:ff:ff:ff")
    req_ = ether_p/arp_p
    results = srp(req_, timeout=2, verbose=False, retry=2, iface=interface)[0]
    return results


def getMacVendor(mac):

    mac = mac.strip().upper()
    with open("vendorMacs.txt", "r", encoding="utf-8") as vendors:
        for i in vendors:
            i = i.strip().split(" (&_&) ")
            if (i[0] == mac):
                return i[1]

    return "UNKNOWN"


def show_ip_mac_vendor(res):

    print("\n\n\n", "_" * 144, file=outputt)
    print("|_______IP________|".ljust(26), "|_______MAC_______|      ",
          "|" + "______VENDOR______".center(91, "_") + "|", file=outputt)
    print("_" * 146, file=outputt)

    for sent, received in res:
        v = " " + colored(getMacVendor(received.hwsrc[:8]), "yellow") + " "
        srcIP = colored(received.psrc, "yellow")
        srcMAC = colored(received.hwsrc, "yellow")
        l = "|" + srcIP.center(30) + " >    " + srcMAC + \
            "    >    " + v.center(100) + "|"
        print(l, file=outputt)

    print("|" + ("_" * 144) + "|", file=outputt)


def show_ip_mac_vendor_hostname(res):

    print("\n\n\n", "_" * 138, file=outputt)
    print("|_____HOSTNAME_____|".ljust(26), "|_______IP________|".ljust(
        23), "|_______MAC_______|      ",  "|" + "______VENDOR______".center(61, "_") + "|", file=outputt)
    print("_" * 140, file=outputt)

    for sent, received in res:
        v = " " + colored(getMacVendor(received.hwsrc[:8]), "yellow") + " "
        srcIP = colored(received.psrc, "yellow")
        srcMAC = colored(received.hwsrc, "yellow")
        hN = colored(getHostName(received.psrc), "yellow")
        l = "|" + hN.center(28) + "   >    " + srcIP.ljust(29) + \
            ">   " + srcMAC + "    >   " + v.center(71) + "|"
        print(l, file=outputt)

    print("|" + ("_" * 138) + "|", file=outputt)


def ip_control():

    if (ipField.count(".") == 3):
        if ("/" in ipField and ipField.count("/") == 1):
            networkID = ipField.split("/")[1]
            if (networkID not in ("8", "16", "24")):
                return False

        ip = ipField.split("/")[0]
        ipoctet = ip.split(".")
        for i in ipoctet:
            if (not (i.isnumeric() and int(i) in range(0, 255))):
                return False

        return True

    else:
        return False


def terminalColorDt():

    if (name == "nt"):

        command1 = "powershell -Command Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1"
        command2 = "powershell -Command Get-ItemPropertyValue HKCU:\Console VirtualTerminalLevel"
        v = run(command2, capture_output=True)

        if (v.returncode != 0) or (v.stdout.strip() != b"1"):
            v2 = run(command1)

            if (v2.returncode != 0):
                print(colored(
                    "\n\n[!]-> Something went wrong, please give admin permission and try again <-[!]\n\n", "red"))
                return False

            return True

        return True

    return True


argumentS = getArguments()
ipField = argumentS.ipField
hostN = argumentS.getHostname
hostN = hostN.lower() if (hostN != None) else "n"
outputt = argumentS.outFile
outputt = stdout if outputt == None else outputt
interface = argumentS.interface


if ((ipField != None) and (ip_control())):

    if (hostN in ("y", "n")):

        if (not terminalColorDt()):
            r = input(
                "You are using Windows and your terminal color may look distorted, do you want to continue? [y/press any key]: ").strip().casefold()

            if (r != "y"):
                print("Closed!")
                quit()

        try:

            chdir(dirname(__file__))

            print("\n\nScan started!\n\n")

            if (outputt != stdout):

                with open(outputt, "a", buffering=True) as outputt:

                    if (hostN == "y"):
                        show_ip_mac_vendor_hostname(discover())

                    else:
                        show_ip_mac_vendor(discover())

            else:
                if (hostN == "y"):
                    show_ip_mac_vendor_hostname(discover())

                else:
                    show_ip_mac_vendor(discover())

        except KeyboardInterrupt:
            print("CTRL + C detected!")

        except:
            print("Error....")

        else:
            print("\n\nScan completed!\n\n")

    else:
        print(
            colored("\n[ ! ] Invalid value entered for hostname parameter [ ! ]\n", "red"))

else:
    print(colored("\n[ ! ] Invalid ip or ip field [ ! ]\n", "blue"))
