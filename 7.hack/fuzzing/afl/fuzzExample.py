import sys
import os

def target_once():
    data = sys.stdin.buffer.read()
    if data:
        _ = len(data)

def main():
    import afl
    afl.init()
    target_once()
    os._exit(0)

if __name__ == "__main__":
    main()
