import socket
import time
import argparse

def _send(sock, data):
    print(f'[Sending "{data}"]')
    sock.send(data.encode())

def _recv(sock):
    try:
        resp = sock.recv(2048)
        return resp.decode()
    except:
        print('[No data received]')
        return None


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', help='Kernel crash scenario', action='store_true')
    parser.add_argument('--ip', default='localhost')
    parser.add_argument('--port', default=8080, type=int)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.ip, args.port))
    s.settimeout(1)

    # What request to send?
    req = ['hello world 1', 'hello world 2 END']
    if args.k:
        req = ['hello world 1', 'hello world 2', 'hello world 3 END']

    for r in req:
        _send(s, r)
        resp = _recv(s)
        if resp:
            print(resp)


    s.close()


if __name__ == '__main__':
    main()

