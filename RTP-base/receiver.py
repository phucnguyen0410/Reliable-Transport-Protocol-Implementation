import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472

START = 0
END = 1
DATA = 2
ACK = 3


def create_packet(packet_type, seq_num, payload=b''):
    """Create a packet with a valid checksum."""

    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )

    checksum = compute_checksum(header / payload)
    header.checksum = checksum

    return bytes(header / payload)


def decode_packet(raw_packet):
    """Decode a packet and verify its checksum."""

    if len(raw_packet) < HEADER_SIZE:
        return None

    if len(raw_packet) > MAX_PACKET_SIZE:
        return None

    header = PacketHeader(raw_packet[:HEADER_SIZE])
    payload = raw_packet[HEADER_SIZE:]

    if header.length != len(payload):
        return None

    received_checksum = header.checksum
    header.checksum = 0

    calculated_checksum = compute_checksum(header / payload)

    if received_checksum != calculated_checksum:
        return None

    return header.type, header.seq_num, payload


def send_ack(sock, address, seq_num):
    """Send a cumulative ACK."""

    ack_packet = create_packet(ACK, seq_num)
    sock.sendto(ack_packet, address)


def receiver(receiver_ip, receiver_port, window_size):

    if window_size <= 0:
        raise ValueError("Window size must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    active_address = None
    expected_seq = 1
    buffer = {}

    try:
        while True:

            raw_packet, address = sock.recvfrom(2048)

            result = decode_packet(raw_packet)

            # Ignore corrupted or invalid packets.
            if result is None:
                continue

            packet_type, seq_num, payload = result

            # 1. Handle START.
            if packet_type == START:

                if active_address is None:
                    active_address = address
                    expected_seq = 1
                    buffer = {}

                if address == active_address:
                    send_ack(sock, address, 1)

                continue

            # Ignore packets from other senders.
            if address != active_address:
                continue

            # 2. Handle DATA.
            if packet_type == DATA:

                if seq_num < expected_seq:
                    # Duplicate packet.
                    send_ack(sock, address, expected_seq)
                    continue

                if seq_num >= expected_seq + window_size:
                    # Packet is outside the receiving window.
                    continue

                # Buffer the packet if it is inside the window.
                if seq_num not in buffer:
                    buffer[seq_num] = payload

                # Deliver all consecutive packets in order.
                while expected_seq in buffer:

                    data = buffer.pop(expected_seq)

                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()

                    expected_seq += 1

                # Send cumulative ACK.
                send_ack(sock, address, expected_seq)

                continue

            # 3. Handle END.
            if packet_type == END:

                if seq_num == expected_seq:
                    send_ack(sock, address, seq_num + 1)
                    break

    finally:
        sock.close()


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "receiver_ip",
        help="The IP address of the receiver"
    )

    parser.add_argument(
        "receiver_port",
        type=int,
        help="The receiver port"
    )

    parser.add_argument(
        "window_size",
        type=int,
        help="Maximum number of outstanding packets"
    )

    args = parser.parse_args()

    receiver(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()
