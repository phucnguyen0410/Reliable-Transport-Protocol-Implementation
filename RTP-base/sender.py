import argparse
import socket
import sys
import time
import select

from utils import PacketHeader, compute_checksum


MAX_PACKET_SIZE = 1472
HEADER_SIZE = 16
MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5

START = 0
END = 1
DATA = 2
ACK = 3


def create_packet(packet_type, seq_num, payload=b''):
    """Create a packet with a valid CRC32 checksum."""

    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )

    packet = header / payload
    header.checksum = compute_checksum(packet)

    return bytes(header / payload)


def decode_packet(raw_packet):
    """Decode a packet and verify its checksum."""

    if len(raw_packet) < HEADER_SIZE:
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


def wait_for_ack(sock, expected_seq):
    """Wait for the ACK of a control packet."""

    while True:
        raw_packet, _ = sock.recvfrom(2048)
        result = decode_packet(raw_packet)

        if result is None:
            continue

        packet_type, seq_num, payload = result

        if packet_type == ACK and seq_num == expected_seq:
            return


def sender(receiver_ip, receiver_port, window_size):

    if window_size <= 0:
        raise ValueError("Window size must be positive")

    receiver_address = (receiver_ip, receiver_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Read the complete input message.
        message = sys.stdin.buffer.read()

        # Split the message into appropriately sized chunks.
        chunks = [
            message[i:i + MAX_DATA_SIZE]
            for i in range(0, len(message), MAX_DATA_SIZE)
        ]

        total_packets = len(chunks)

        # 1. Send START packet.
        start_packet = create_packet(START, 0)
        sock.sendto(start_packet, receiver_address)

        wait_for_ack(sock, 1)

        # 2. Initialize the sliding window.
        base = 1
        next_seq = 1

        outstanding = {}

        timer_start = None

        # 3. Send DATA packets reliably.
        while base <= total_packets:

            # Fill the current sending window.
            while (
                next_seq <= total_packets
                and next_seq < base + window_size
            ):
                packet = create_packet(
                    DATA,
                    next_seq,
                    chunks[next_seq - 1]
                )

                sock.sendto(packet, receiver_address)

                outstanding[next_seq] = packet

                if timer_start is None:
                    timer_start = time.monotonic()

                next_seq += 1

            # Calculate remaining timer duration.
            elapsed = time.monotonic() - timer_start
            remaining = max(0, TIMEOUT - elapsed)

            readable, _, _ = select.select(
                [sock], [], [], remaining
            )

            if readable:

                raw_packet, _ = sock.recvfrom(2048)
                result = decode_packet(raw_packet)

                if result is None:
                    continue

                packet_type, ack_num, _ = result

                if packet_type != ACK:
                    continue

                # Accept only valid cumulative ACKs.
                if base < ack_num <= next_seq:

                    base = ack_num

                    # Remove acknowledged packets.
                    outstanding = {
                        seq: packet
                        for seq, packet in outstanding.items()
                        if seq >= base
                    }

                    # Reset timer when the window advances.
                    if outstanding:
                        timer_start = time.monotonic()
                    else:
                        timer_start = None

            else:

                # Timeout: retransmit all unacknowledged
                # packets in the current window.
                for packet in outstanding.values():
                    sock.sendto(packet, receiver_address)

                timer_start = time.monotonic()

        # 4. Send END packet.
        end_seq = total_packets + 1

        end_packet = create_packet(END, end_seq)

        sock.sendto(end_packet, receiver_address)

        # Wait at most 500 milliseconds for END ACK.
        readable, _, _ = select.select(
            [sock], [], [], TIMEOUT
        )

        if readable:
            raw_packet, _ = sock.recvfrom(2048)
            result = decode_packet(raw_packet)

            if result is not None:
                packet_type, ack_num, _ = result

                if packet_type == ACK and ack_num == end_seq + 1:
                    pass

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

    sender(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()
