import datetime
import json
import signal
import socket
import struct
import sys
import os
from enum import Enum
from collections import namedtuple
from pprint import pprint

import soco
from soco import events_twisted
from twisted.internet import reactor, task
from twisted.internet.protocol import DatagramProtocol
from twisted.web import static
from twisted.web.resource import Resource
from twisted.web.server import Site

soco.config.EVENTS_MODULE = events_twisted

print("Looking for Sonos devices")
device = soco.discovery.any_soco()

device = device.group.coordinator

SeqDetails = namedtuple("SequenceInfo", ["num_frames", "fseq_file", "stream_path", "duration", "title"])

class FPPSyncType(Enum):
    Start = 0
    Stop = 1
    Sync = 2
    Open = 3

def int_from_bytes(bytes):
    # TODO: only valid in python 3.2+
    return int.from_bytes(bytes, 'little')

def get_number_of_frames(file: str):
    with open(file, "rb") as f:
        magic = f.read(4)
        if magic != b'PSEQ':
            raise ParserError('invalid fseq file magic: %s', magic)

        f.read(2) # Channel Data Start

        minor_version = int_from_bytes(f.read(1))
        major_version = int_from_bytes(f.read(1))

        version = (major_version, minor_version)
        if major_version != 2:
            raise ParserError('unrecognized fseq file version: %s' % version)

        f.read(6)

        number_of_frames = int_from_bytes(f.read(4))

        return number_of_frames

def load_show_plan() -> list[SeqDetails]:
    result = []
    with open("show_plan.json") as f:
        show_plan = json.load(f)
        for seq in show_plan:
            fseq_file_name = seq["fseq_file"]
            num_frames = get_number_of_frames(os.path.join("show", fseq_file_name))
            result.append(SeqDetails(num_frames, fseq_file_name, seq["stream_path"], seq['seconds'], seq['title']))
    return result

fseq_table = load_show_plan()
song_by_filename = {song.title: song for song in fseq_table}

MULTICAST_ADDRESS = "239.70.80.80"
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


def get_lan_addr_str() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.2.1", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def get_lan_addr():
    return socket.inet_aton(get_lan_addr_str())


def encode_str(string: str, target_length: int) -> bytes:
    return string.ljust(target_length, "\0").encode("ascii")


def parse_time(time_str):
    """
    Parse time string in format 'HH:MM:SS' into total seconds.

    Args:
        time_str (str): Time string in format 'HH:MM:SS'.

    Returns:
        int: Total seconds.
    """
    h, m, s = map(int, time_str.split(":"))
    return h * 3600 + m * 60 + s


def encode_sync_packet(
    sequence_name: str, fseq_file: SeqDetails, sync_action: FPPSyncType, seconds_elapsed: int, total_seconds: int
):
    return struct.pack(
        f"<4sBHBBIf{len(sequence_name)}sB",
        "FPPD".encode("ascii"),
        1,  # Packet Type
        (11 + len(sequence_name)),  # packet length
        sync_action.value,  # Sync Action
        0,  # Sync Type
        int((seconds_elapsed / total_seconds) * fseq_file.num_frames),  # Frame Number
        seconds_elapsed,  # Seconds Elapsed
        sequence_name.encode("ascii"),  # File Name
        0,  # Null terminated string
    )


def encode_hello_packet():
    return struct.pack(
        "<4sBHBBBHHB4s65s41s41s121s14s",
        "FPPD".encode("ascii"),
        4,  # Message Type
        294,  # Extra Data Length
        3,
        0,
        1,  # Hardware Type
        512,  # version major
        512,  # version minor
        4,  # operating mode
        get_lan_addr(),
        encode_str("SONOSSYNC", 65),  # hostname
        encode_str("1.1", 41),
        encode_str("softwareemulated", 41),
        encode_str("0-1", 121),
        "".ljust(14, "\0").encode("ascii"),
    )

song = None

def refresh_sonos_start():
    global start_time
    cur_time = datetime.datetime.now()
    pos = device.get_current_track_info()['position']
    position = parse_time(pos)
    start_time = cur_time - datetime.timedelta(seconds=position)

def sync_beat():
    if state == 'PLAYING':
        try:
            cur_time = datetime.datetime.now()

            pos = device.get_current_track_info()['position']
            position = parse_time(pos)
            print(pos)
            sonos_listener.send_sync_packet(song, FPPSyncType.Sync, position, song.duration)
        except Exception as e:
            print(e)

syncTask = task.LoopingCall(sync_beat)

class MulticastListener(DatagramProtocol):
    def startProtocol(self):
        # Join the multicast group
        self.transport.joinGroup(MULTICAST_ADDRESS, get_lan_addr_str())

        # Introduce ourselves to the FPP MultiSync swarm
        self.transport.write(encode_hello_packet(), (MULTICAST_ADDRESS, PORT))

    def send_sync_packet(self, fseq_file: SeqDetails, action: FPPSyncType, seconds_elapsed: int, total_seconds: int):
        self.transport.write(encode_sync_packet(fseq_file.fseq_file, fseq_file, action, seconds_elapsed, total_seconds), (MULTICAST_ADDRESS, PORT))

    def send_blanking_data(self):
        pkt = struct.pack(
            "<4sBH",
            "FPPD".encode("ascii"),
            3,  # Message Type
            0,  # Extra Data Length
        )
        self.transport.write(pkt, (MULTICAST_ADDRESS, PORT))

    def datagramReceived(self, datagram, addr):
        if datagram[:4].decode("utf-8") != "FPPD":
            print("Dropping non FPPD packet", str(datagram[:4]))
            return
        #print(f"Received packet from {addr}")


sonos_listener = MulticastListener()

def process_sonos_packet(event: soco.events_base.Event):
    global state
    global start_time
    global song

    song = song_by_filename[event.variables['current_track_meta_data'].title]
    # elapsed = parse_time(event.variables['current_track_position'])
    duration = song.duration

    # start_time = cur_time - datetime.timedelta(seconds=elapsed)

    state = event.variables['transport_state']
    if state == 'TRANSITIONING':
        print(f"Transitioning to {song.fseq_file}")
        sonos_listener.send_sync_packet(song, FPPSyncType.Start, 0, duration)
        if not syncTask.running:
            syncTask.start(1)
    elif state == 'PLAYING':
        if not syncTask.running:
            syncTask.start(1)
        refresh_sonos_start()
    elif state == 'STOPPED' or state == 'PAUSED_PLAYBACK':
        if syncTask.running:
            syncTask.stop()
        sonos_listener.send_sync_packet(song, FPPSyncType.Stop, 0, duration)
        sonos_listener.send_blanking_data()
    # if event.variables["transport_state"] == "PLAYING" or True:
    # print(start_time, duration)
    # sonos_listener.transport.write(
    #    encode_sync_packet("romeo.fseq", fseq_table[0], 0, duration),
    #    ("192.168.2.199", PORT),
    # )
    # print("Packet")
    # pprint(event)


def main():
    global device
    device = soco.discovery.by_name("Living Room")

    device = device.group.coordinator
    sub = device.avTransport.subscribe(auto_renew=True).subscription
    sub.callback = process_sonos_packet

    def before_shutdown():
        sub.unsubscribe()
        events_twisted.event_listener.stop()

    reactor.addSystemEventTrigger("before", "shutdown", before_shutdown)

    device.clear_queue()
    local_ip = get_lan_addr_str()
    for show in fseq_table:
        url = f"http://{local_ip}:8080/{show.stream_path}"
        print(url)
        device.add_uri_to_queue(url)


if __name__ == "__main__":
    print("Listening for FPP multisync packets on", MULTICAST_ADDRESS, ":", PORT)
    reactor.listenMulticast(PORT, sonos_listener, listenMultiple=True)
    reactor.listenTCP(8080, Site(static.File("./songs")))
    reactor.callWhenRunning(main)
    reactor.run()
