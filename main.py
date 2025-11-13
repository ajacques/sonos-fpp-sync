import datetime
import json
import signal
import socket
import struct
import sys
from collections import namedtuple
from pprint import pprint

import soco
from soco import events_twisted
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.web import static
from twisted.web.resource import Resource
from twisted.web.server import Site

import fseq

soco.config.EVENTS_MODULE = events_twisted
# logging.basicConfig(level=logging.DEBUG)

print("Looking for Sonos devices")
device = soco.discovery.any_soco()

device = device.group.coordinator

SeqDetails = namedtuple("SequenceInfo", ["num_frames", "fseq_file", "stream_path"])


def load_show_plan() -> list[SeqDetails]:
    result = []
    with open("show_plan.json") as f:
        show_plan = json.load(f)
        for seq in show_plan:
            fseq_file_name = seq["fseq_file"]
            with open(fseq_file_name, "rb") as fseq_file_fd:
                fseq_file = fseq.parse(fseq_file_fd)
                num_frames = fseq_file.number_of_frames
            result.append(SeqDetails(num_frames, fseq_file_name, seq["stream_path"]))
    return result


fseq_table = load_show_plan()

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

print("Listening for FPP multisync packets on", MULTICAST_ADDRESS, ":", PORT)


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
    sequence_name: str, fseq_file: SeqDetails, seconds_elapsed, total_seconds
):
    return struct.pack(
        f"<4sBHBBIf{len(sequence_name)}sB",
        "FPPD".encode("ascii"),
        1,  # Packet Type
        (11 + len(sequence_name)),  # packet length
        2,  # Sync Action
        0,  # Sync Type
        int(
            (seconds_elapsed / total_seconds) * fseq_file.number_of_frames
        ),  # Frame Number
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


class MulticastListener(DatagramProtocol):
    def startProtocol(self):
        # Join the multicast group
        self.transport.joinGroup(MULTICAST_ADDRESS)

        # Introduce ourselves to the FPP MultiSync swarm
        self.transport.write(encode_hello_packet(), (MULTICAST_ADDRESS, PORT))

    def datagramReceived(self, data, address):
        if data[:4].decode("utf-8") != "FPPD":
            print("Dropping non FPPD packet", str(data[:4]))
            return
        print(f"Received packet from {address}")


sonos_listener = MulticastListener()


def process_sonos_packet(event: soco.events_base.Event):
    pprint(event.variables)

    cur_time = datetime.datetime.now()
    # elapsed = parse_time(event.variables['current_track_position'])
    duration = parse_time(event.variables["current_track_duration"])

    # start_time = cur_time - datetime.timedelta(seconds=elapsed)

    event.variables
    if event.variables["transport_state"] == "PLAYING" or True:
        # print(start_time, duration)
        sonos_listener.transport.write(
            encode_sync_packet("romeo.fseq", fseq_table[0], 0, duration),
            ("192.168.2.199", PORT),
        )
    # print("Packet")
    # pprint(event)


def main():
    device = soco.discovery.any_soco()

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
        device.add_uri_to_queue(f"http://{local_ip}:8080/{show.stream_path}")


if __name__ == "__main__":
    reactor.listenMulticast(PORT, sonos_listener, listenMultiple=True)
    reactor.listenTCP(8080, Site(static.File("./songs")))
    reactor.callWhenRunning(main)
    reactor.run()
