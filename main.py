from collections import namedtuple
from pprint import pprint
from soco import events_twisted
from twisted.internet import reactor, udp
from twisted.internet.protocol import DatagramProtocol
import fseq
import glob
import logging
import signal
import socket
import soco
import struct
import datetime
import sys
import pathlib
soco.config.EVENTS_MODULE = events_twisted
#logging.basicConfig(level=logging.DEBUG)

print("Looking for Sonos devices")
device = soco.discovery.any_soco()

device = device.group.coordinator

SeqDetails = namedtuple('SequenceInfo', ['num_frames'])

fseq_table: dict[str, int] = {}


for fseq_file_name in glob.glob('../../xlights-test/**.fseq'):
    with open(fseq_file_name, 'rb') as f:
        fseq_file = fseq.parse(f)
        fseq_table[fseq_file_name] = fseq_file.number_of_frames

print(fseq_table)

print(device)
track_info = device.get_current_track_info()

MULTICAST_ADDRESS = '239.70.80.80'
PORT = 32320


def signal_handler(sig, frame):
    """
    Signal handler for SIGINT (Ctrl+C)
    """
    print("\nReceived SIGINT (Ctrl+C). Exiting gracefully...")
    reactor.stop()
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

print("Listening for FPP multisync packets on", MULTICAST_ADDRESS, ":", PORT)

def get_lan_addr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.2.1", 80))
        return socket.inet_aton(s.getsockname()[0])
    finally:
        s.close()

def encode_str(string: str, target_length: int) -> str:
    return string.ljust(target_length, '\0').encode('ascii')

def parse_time(time_str):
    """
    Parse time string in format 'HH:MM:SS' into total seconds.
    
    Args:
        time_str (str): Time string in format 'HH:MM:SS'.
    
    Returns:
        int: Total seconds.
    """
    h, m, s = map(int, time_str.split(':'))
    return h * 3600 + m * 60 + s

seconds_elapsed = parse_time(track_info['position'])
total_seconds = parse_time(track_info['duration'])

def encode_sync_packet(sequence_name: str):
    return struct.pack(
        f'<4sBHBBIf{len(sequence_name)}sB', 
        'FPPD'.encode('ascii'), 
        1, # Packet Type
        (11 + len(sequence_name)), # packet length
        2, # Sync Action
        0, # Sync Type
        int((seconds_elapsed / total_seconds) * fseq_file.number_of_frames), # Frame Number
        seconds_elapsed, # Seconds Elapsed
        sequence_name.encode('ascii'), # File Name
        0 # Null terminated string
    )

def encode_hello_packet():
    return struct.pack(
        '<4sBHBBBHHB4s65s41s41s121s', 
        'FPPD'.encode('ascii'), 
        4, # Message Type
        294, # Extra Data Length
        0, 
        0, 
        1, 
        2, # version major
        2, # version minor
        4, # operating mode
        get_lan_addr(), 
        encode_str('SONOSSYNC', 65), # hostname
        encode_str('version', 41), 
        encode_str('softwareemulated', 41), 
        encode_str('1-2', 121)
    )

class MulticastListener(DatagramProtocol):
    def startProtocol(self):
        # Join the multicast group
        self.transport.joinGroup(MULTICAST_ADDRESS)  # Replace with your multicast address

        # Introduce ourselves to the FPP MultiSync swarm
        self.transport.write(encode_hello_packet(), (MULTICAST_ADDRESS, PORT))

    def datagramReceived(self, data, address):
        if data[:4].decode('utf-8') != 'FPPD':
            print("Dropping non FPPD packet", str(data[:4]))
            return
        print(f"Received packet from {address}")


def process_sonos_packet(event: soco.events_base.Event):
    pprint(event.variables)
    cur_time = datetime.datetime.now()
    duration = parse_time(event.variables['current_track_duration'])

    event.variables
    #print("Packet")
    #pprint(event)


def main():
    device = soco.discovery.any_soco()

    device = device.group.coordinator
    # Subscribe to ZGT evI ents
    sub = device.avTransport.subscribe(auto_renew=True).subscription
    # print out the events as they arise
    sub.callback = process_sonos_packet

    def before_shutdown():
        sub.unsubscribe()
        events_twisted.event_listener.stop()

    reactor.addSystemEventTrigger('before', 'shutdown', before_shutdown)

if __name__=='__main__':
    reactor.listenMulticast(PORT, MulticastListener(), listenMultiple=True)
    reactor.callWhenRunning(main)
    reactor.run()
