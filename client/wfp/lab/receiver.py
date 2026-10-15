"""Controlled independent VM receiver. No firewall, route or service changes.

Run on a disposable peer, never on SethLinux. UDP/53 may require privilege.
Use packet capture alongside this application log: no received payload does
not prove that no packet escaped the sender.
"""
import argparse
import datetime
import json
import selectors
import socket


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', required=True)
    parser.add_argument('--tcp-port', type=int, default=8443)
    parser.add_argument('--udp-port', type=int, default=53)
    args = parser.parse_args()
    selector = selectors.DefaultSelector()
    for kind, port in ((socket.SOCK_STREAM, args.tcp_port), (socket.SOCK_DGRAM, args.udp_port)):
        endpoint = socket.socket(socket.AF_INET, kind)
        endpoint.bind((args.bind, port))
        if kind == socket.SOCK_STREAM:
            endpoint.listen()
        endpoint.setblocking(False)
        selector.register(endpoint, selectors.EVENT_READ, 'listen' if kind == socket.SOCK_STREAM else 'udp')
    try:
        while True:
            for key, _ in selector.select():
                endpoint = key.fileobj
                if key.data == 'listen':
                    client, peer = endpoint.accept()
                    client.setblocking(False)
                    selector.register(client, selectors.EVENT_READ, 'tcp')
                    continue
                if key.data == 'udp':
                    payload, peer = endpoint.recvfrom(4096)
                else:
                    payload = endpoint.recv(4096)
                    peer = endpoint.getpeername()
                    if not payload:
                        selector.unregister(endpoint)
                        endpoint.close()
                        continue
                print(json.dumps({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'protocol': key.data, 'peer': peer, 'payload_hex': payload.hex()}), flush=True)
    finally:
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()


if __name__ == '__main__':
    main()
