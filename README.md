# Python Network Discover


## Warning!

If you are going to use it on windows, npcap or WinPcap must be installed.


## Usage:

In this usage, it fetches the ip and mac addresses of the devices on the network.

* `python network_discover.py --ipField 192.168.1.0/24 --interface wlan0`

#

In this usage, it shows the ip address, mac address and host name of the devices on the network.

* `python network_discover.py --ipField 192.168.1.0/24 --interface wlan0 --getHostname y`

## Write File

* With the --outFile parameter, information can be written to the file.