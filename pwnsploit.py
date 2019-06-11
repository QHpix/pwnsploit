#!/usr/bin/python
from pwn import *
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('-t','--timeout',type=int)
parser.add_argument('-b','--bof',action='store_true')
parser.add_argument('-f','--format',action='store_true')
parser.add_argument('file')

def check_bof(file, timeout=1,payload_size=1000,tries=1):
    payload = cyclic(payload_size)

    p = process(file)
    if p.can_recv(timeout):
        while True:
            if p.recv(timeout=timeout) == '':
                break

    p.sendline(payload)
    p.wait()

    try:
        core = Coredump('./core')
        if '64' in core.arch:
            rsp = core.read(core.rsp,4)
            assert rsp in payload
            length = cyclic_find(rsp)
        else:
            assert pack(core.eip) in payload
            length = cyclic_find(core.eip)
        vulnerable = True
    except:
        vulnerable = False
    p.close()
    if vulnerable:
        log.success('Executable is vulnerable to buffer overflow')
        log.success('Padding length: {}'.format(length))

    elif tries > 10:
        log.info('Executable is NOT vulnerable to buffer overflow')

    else:
        check_bof(file,timeout,payload_size=(payload_size+100),tries=(tries+1))

def check_format(file, timeout=1):
    
    payload = 'AAAA.'+'%x.'*15

    p = process(file)

    if p.can_recv(timeout):
        while True:
            if p.recv(timeout=timeout) == '':
                break

    p.sendline(payload)
    try:
        output = p.recv()
        
        if '41414141' in output:
            log.success('Executable is vulnerable to format string attack')

        else:
            log.info('Executable is NOT vulnerable to format string attack')
    except:
        log.info('Cannot determine if executable is vulnerable to format string attack')
        p.close()

def main():
    args = parser.parse_args()
    if args.timeout == None:
        args.timeout = 1
    if args.bof:
        check_bof(args.file, args.timeout)
    elif args.format:
        check_format(args.file, args.timeout)
    else:
        check_bof(args.file, args.timeout)
        check_format(args.file, args.timeout)

if __name__ == '__main__':
    main()
