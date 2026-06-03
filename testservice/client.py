#!/usr/bin/env python3
"""
Test gRPC client for protosnoop verification.
Run: python3 client.py [--port 50051] [--tls] [--loop] [--delay 1.0]
"""
import argparse
import time
import sys

import grpc
import test_pb2
import test_pb2_grpc


def run(stub, verbose=True):
    def log(label, resp):
        if verbose:
            print(f"\n── {label}")
            print(f"   {resp}")

    # 1. Simple echo
    resp = stub.Echo(test_pb2.EchoRequest(message="hello protosnoop", repeat=3))
    log("Echo(message='hello protosnoop', repeat=3)", resp)

    # 2. Echo with unicode to exercise string fields
    resp = stub.Echo(test_pb2.EchoRequest(message="café résumé", repeat=1))
    log("Echo(message='café résumé', repeat=1)", resp)

    # 3. GetUser — returns nested Address + repeated tags
    for uid in [1, 2, 3]:
        resp = stub.GetUser(test_pb2.GetUserRequest(id=uid))
        log(f"GetUser(id={uid})", resp)

    # 4. ListItems — returns repeated Item with enum + bytes fields
    resp = stub.ListItems(test_pb2.ListRequest(limit=5))
    log("ListItems(limit=5)", resp)

    # 5. ListItems with limit
    resp = stub.ListItems(test_pb2.ListRequest(limit=2))
    log("ListItems(limit=2)", resp)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port",  type=int,   default=50051)
    p.add_argument("--host",  default="localhost")
    p.add_argument("--tls",   action="store_true")
    p.add_argument("--loop",  action="store_true", help="repeat forever (good for watching in protosnoop)")
    p.add_argument("--reconnect", action="store_true", help="open a fresh connection each loop iteration")
    p.add_argument("--delay", type=float, default=1.5, help="seconds between loop iterations")
    args = p.parse_args()

    target = f"{args.host}:{args.port}"

    if args.tls:
        try:
            with open("server.crt", "rb") as f: crt = f.read()
        except FileNotFoundError:
            print("TLS: server.crt not found", file=sys.stderr)
            sys.exit(1)
        creds = grpc.ssl_channel_credentials(root_certificates=crt)
        channel = grpc.secure_channel(target, creds)
        print(f"[client] connecting to {target} (TLS)")
    else:
        channel = grpc.insecure_channel(target)
        print(f"[client] connecting to {target} (plaintext)")

    stub = test_pb2_grpc.TestServiceStub(channel)

    if args.loop:
        print("[client] looping — Ctrl+C to stop\n")
        i = 0
        while True:
            print(f"── iteration {i} ──")
            if args.reconnect and i > 0:
                # Fresh HTTP/2 connection each round, so a packet capture that
                # attaches mid-run still sees a connection preface + full stream.
                channel.close()
                channel = grpc.insecure_channel(target)
                stub = test_pb2_grpc.TestServiceStub(channel)
            try:
                run(stub, verbose=True)
            except grpc.RpcError as e:
                print(f"[client] RPC error: {e.code()} {e.details()}", file=sys.stderr)
            i += 1
            time.sleep(args.delay)
    else:
        try:
            run(stub, verbose=True)
            print("\n[client] done")
        except grpc.RpcError as e:
            print(f"[client] RPC error: {e.code()} {e.details()}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
