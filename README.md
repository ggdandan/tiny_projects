# Python driver

This is the Python driver for the NS1 pcap programming challenge.  Run it as:

```bash
$ ./driver.py PCAP_FILE
```

NOTE: The interpreter declared by the script is `python3`.  If that's not the
name of your interpreter you'll need to run the script by giving it to your
interpreter directly.

## Requirements

* Python 3  (Tested with 3.6.)
* [Scapy](https://scapy.net/) library

You can install the required dependencies using:

```bash
$ pip install -r requirements.txt
```

## Solution guidelines

The Scapy library has a lot of functionality, some of which, if used, would
make parts of this challenge trivial.  Please respect the spirit of the
challenge and only use Scapy functionality for things not related to the task
at-hand.  That is, write the parsing application payloads, calculating
statistics, etc. parts yourself.

