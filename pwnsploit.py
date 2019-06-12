#!/usr/bin/python
from pwn import *
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--timeout', type=int)
parser.add_argument('-b', '--bof', action='store_true')
parser.add_argument('--format', action='store_true')
parser.add_argument('-H', '--host')
parser.add_argument('-p', '--port', type=int)
parser.add_argument('-f', '--file')

def check_bof(file, timeout=1, payload_size=1000, tries=1):
    
    payload = cyclic(payload_size) #generate a pattern of `payload_size`

    p = process(file)
    #receive until there is no more output
    if p.can_recv(timeout):
        while True:
            if p.recv(timeout=timeout) == '':
                break

    p.sendline(payload)
    p.wait()

    #check if the instruction pointer got overwritten with the generated pattern
    try:
        core = Coredump('./core')
        if '64' in core.arch:
            rsp = core.read(core.rsp, 4)
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
        elf = ELF(file)
        log.success('Executable is vulnerable to buffer overflow')
        log.success('Padding length: {}'.format(length))
        if elf.nx:
            log.info('NX is enabled, so ROP may be required')

    elif tries > 10:
        log.info('Executable is NOT vulnerable to buffer overflow')

    else:
        check_bof(file, timeout, payload_size=(payload_size+100), tries=(tries+1))

def check_format(file, timeout=1, host=None, port=None):
    
    payload = 'AAAA.'+'%x.'*15

    if host and port:
        p = remote(host, port)
    else:
        p = process(file)

    #receive until there is no more output
    if p.can_recv(timeout):
        while True:
            if p.recv(timeout=timeout) == '':
                break

    p.sendline(payload)
    #check if 'AAAA' is displayed in hex format in the output
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

    print('                                _       _ _   ')
    print('                               | |     (_) |  ')
    print('  _ ____      ___ __  ___ _ __ | | ___  _| |_ ')
    print(' | \'_ \\ \\ /\\ / / \'_ \\/ __| \'_ \\| |/ _ \\| | __|')
    print(' | |_) \\ V  V /| | | \\__ \\ |_) | | (_) | | |_ ')
    print(' | .__/ \\_/\\_/ |_| |_|___/ .__/|_|\\___/|_|\\__|')
    print(' | |                     | |                  ')
    print(' |_|                     |_|                  ')
    print('By QHpix.')
    args = parser.parse_args()
    if not args.file and not args.host:
        print('No method selected, please do pwnsploit.py -h for more info')
        exit()
    if args.timeout == None:
        args.timeout = 1

    if args.bof:
        check_bof(args.file, args.timeout)

    elif args.format:
        check_format(args.file, args.timeout, args.host, args.port)

    else:
        check_bof(args.file, args.timeout)
        check_format(args.file, args.timeout, args.host, args.port)

if __name__ == '__main__':
    main()
