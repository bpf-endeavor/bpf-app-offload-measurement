import socket
import threading
import time
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='Server ip address')
    parser.add_argument('port', type=int, help='Server port address')
    args = parser.parse_args()
    return args

args = parse_args()
dest = (args.host, args.port)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(dest)
msg = 'Hello World! this is a benchmark: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'.encode()

running = True
sent_cntr = 0
rate = 1 # request per second

def worker():
    global sent_cntr
    print(f'Sending packets to: {dest[0]}:{dest[1]}')
    while running:
        client.send(msg)
        # print('sent')
        # resp = client.recv(2048)
        # print(resp)
        sent_cntr += 1
        if rate < 6000:
            time.sleep(1 / rate)

# start worker
t = threading.Thread(target=worker)
t.start()
ctrl_running = True
while ctrl_running:
    print('Running: rate:', rate)
    try:
        command = input('(rate, done) > ')
    except:
        command = 'done'
    command = command.strip()
    if command == 'done':
        running = False
        t.join()
        ctrl_running = False
        break
    elif command == 'rate':
        while True:
            try:
                rate = int(input('Request per second? '))
                break
            except:
                print('Failed to parse int')
                continue
    else:
        print('Sent:', sent_cntr)
