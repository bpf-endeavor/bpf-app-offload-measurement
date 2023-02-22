import sys
import socket
import threading
import time
import argparse
import select


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
rate = 1000 # request per second

def worker():
    global sent_cntr
    print(f'Sending packets to: {dest[0]}:{dest[1]}')
    while running:
        client.send(msg)
        # print('sent')
        # resp = client.recv(2048)
        # print(resp)
        sent_cntr += 1
        sleep_time = (1 / rate) * 0.8
        time.sleep(sleep_time)

def main():
    global sent_cntr
    global running
    global rate
    # start worker
    t = threading.Thread(target=worker)
    t.start()

    # TODO: handle SIGINT
    ctrl_running = True

    last_report_time = time.time()
    last_report_value = 0

    list_fd = select.poll()
    list_fd.register(sys.stdin, select.POLLIN | select.POLLHUP | select.POLLERR)

    while ctrl_running:
        print('Running: rate:', rate)
        print('(rate, done) > ', end='')
        sys.stdout.flush()
        res = list_fd.poll(2000)
        if res:
            try:
                command = input()
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
        else:
            now = time.time()
            diff = now - last_report_time
            value = sent_cntr
            tput = (value - last_report_value) / diff
            last_report_time = now
            last_report_value = value
            print('\r', ' '*40, '\r', end='', sep='')
            print('Throughput:', tput)



if __name__ == '__main__':
    main()
