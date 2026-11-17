#!/usr/bin/env python3
"""Exercise the real nftables guard in disposable Linux network namespaces.

Run as root. No packets leave the disposable network; no host firewall is changed.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

sys.dont_write_bytecode = True
SCRIPT = str(Path(__file__).resolve())
UID = 65534
PORT = 23111


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def fixtures(ports, uid=None):
    listeners = []
    datagrams = []
    for family, host in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        for port in ports:
            listener = socket.socket(family)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((host, port))
            listener.listen()
            listeners.append(listener)
            if port == 53:
                udp = socket.socket(family, socket.SOCK_DGRAM)
                if family == socket.AF_INET6:
                    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.bind(("127.0.0.53" if family == socket.AF_INET else "::1", port))
                datagrams.append(udp)
    if uid is not None:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    def serve(listener):
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b"ok")

    for listener in listeners:
        threading.Thread(target=serve, args=(listener,), daemon=True).start()
    def serve_udp(listener):
        while True:
            _, remote = listener.recvfrom(512)
            listener.sendto(b"ok", remote)
    for listener in datagrams:
        threading.Thread(target=serve_udp, args=(listener,), daemon=True).start()
    print("ready", flush=True)
    threading.Event().wait()


def probe(host, port, uid, udp=False):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    try:
        if udp:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            connection = socket.socket(family, socket.SOCK_DGRAM)
            connection.settimeout(1)
            connection.connect((host, port))
            connection.send(b"query")
        else:
            connection = socket.create_connection((host, port), timeout=1)
        with connection:
            assert connection.recv(2) == b"ok"
        print("allowed")
    except OSError:
        print("blocked")


def integration():
    spec = importlib.util.spec_from_file_location("egress", Path(SCRIPT).with_name("render-egress-policy.py"))
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    config = {"uid": UID, "allow_tcp": [{"address": "127.0.0.1", "port": 18788},
                                        {"address": "::1", "port": 18788}],
              "dns_servers": ["127.0.0.53", "::1"]}
    # Reject configuration that could produce an injection or target all root services.
    for bad in [{**config, "uid": 0}, {**config, "uid": True},
                {**config, "dns_servers": ["127.0.0.1; flush ruleset"]},
                {**config, "allow_tcp": [{"address": "localhost", "port": 53}]},
                {**config, "allow_tcp": [{"address": "::1", "port": True}]}]:
        try:
            renderer.render(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe configuration was accepted")
    policy = renderer.render(config)
    peer = f"wb-test-{os.getpid()}"
    children = []
    try:
        run("ip", "link", "set", "lo", "up")
        run("ip", "netns", "add", peer)
        run("ip", "link", "add", "wb-a", "type", "veth", "peer", "name", "wb-b")
        run("ip", "link", "set", "wb-b", "netns", peer)
        run("ip", "address", "add", "10.9.0.1/24", "dev", "wb-a")
        run("ip", "-6", "address", "add", "fd42::1/64", "dev", "wb-a", "nodad")
        run("ip", "link", "set", "wb-a", "up")
        run("ip", "netns", "exec", peer, "ip", "link", "set", "lo", "up")
        run("ip", "netns", "exec", peer, "ip", "link", "set", "wb-b", "up")
        for value in ["10.9.0.2/24", "169.254.169.254/32", "100.64.0.2/32", "93.184.216.34/32"]:
            run("ip", "netns", "exec", peer, "ip", "address", "add", value, "dev", "wb-b")
        for value in ["fd42::2/64", "2606:4700::1111/128"]:
            run("ip", "netns", "exec", peer, "ip", "-6", "address", "add", value, "dev", "wb-b", "nodad")
        run("ip", "route", "add", "default", "via", "10.9.0.2")
        run("ip", "-6", "route", "add", "default", "via", "fd42::2")
        run("ip", "address", "add", "93.184.216.35/32", "dev", "lo")
        for args in [["ip", "netns", "exec", peer, sys.executable, SCRIPT, "--fixtures", str(PORT)],
                     [sys.executable, SCRIPT, "--fixtures", "53,18788,18789"],
                     [sys.executable, SCRIPT, "--daemon"]]:
            child = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
            children.append(child)
            assert child.stdout.readline().strip() == "ready"

        def check(host, port, expected, uid=UID):
            actual = run(sys.executable, SCRIPT, "--probe", host, str(port), str(uid)).stdout.strip()
            assert actual == expected, (host, port, uid, actual, expected)

        blocked = [("127.0.0.1", 18789), ("::1", 18789), ("10.9.0.2", PORT),
                   ("169.254.169.254", PORT), ("100.64.0.2", PORT), ("fd42::2", PORT),
                   ("93.184.216.35", 18789)]
        allowed = [("127.0.0.1", 18788), ("::1", 18788), ("127.0.0.53", 53), ("::1", 53),
                   ("93.184.216.34", PORT), ("2606:4700::1111", PORT)]
        for host, port in blocked + allowed:
            check(host, port, "allowed")
        for host in ["127.0.0.53", "::1"]:
            assert run(sys.executable, SCRIPT, "--probe", host, "53", str(UID), "udp").stdout.strip() == "allowed", host
        run("nft", "--check", "--file", "-", input=policy)
        run("nft", "--file", "-", input=policy)
        run("nft", "--file", "-", input=policy)  # Atomic reload must be repeatable.
        for host, port in blocked:
            check(host, port, "blocked")
            check(host, port, "allowed", uid=0)  # Other services retain access.
        for host, port in allowed:
            check(host, port, "allowed")
        for host in ["127.0.0.53", "::1"]:
            assert run(sys.executable, SCRIPT, "--probe", host, "53", str(UID), "udp").stdout.strip() == "allowed", host
        # A reverse proxy on a private address can still read daemon responses.
        assert run("ip", "netns", "exec", peer, sys.executable, SCRIPT,
                   "--probe", "10.9.0.1", "23112", "0").stdout.strip() == "allowed"
        print(json.dumps({"result": "passed", "blocked_destinations": len(blocked),
                          "allowed_destinations": len(allowed), "other_uid_unchanged": True,
                          "private_client_reply": True, "repeatable_reload": True, "udp_dns": True}))
    finally:
        for child in children:
            child.terminate()
            child.wait(timeout=5)
        subprocess.run(["ip", "netns", "delete", peer], check=False, capture_output=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixtures"]:
        fixtures([int(port) for port in sys.argv[2].split(",")])
    elif sys.argv[1:2] == ["--daemon"]:
        fixtures([23112], UID)
    elif sys.argv[1:2] == ["--probe"]:
        probe(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5:] == ["udp"])
    elif sys.argv[1:2] == ["--isolated"]:
        integration()
    else:
        subprocess.run(["unshare", "--net", sys.executable, SCRIPT, "--isolated"], check=True)
        print("Isolated nftables integration passed")
