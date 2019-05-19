#!/usr/bin/python3

# from scapy.all import *
from kamene.all import * # support pcapng
import sys
import requests
from collections import Counter

# mac vendor cache
MAC_CACHE = {}

packets = rdpcap(sys.argv[1])

profiles = {} # dhcp starvation
arp_stat = {} # arp spoofing
count = 0

def bytes_2_mac(mac_bytes=b''):
    return ':'.join(['{:02x}'.format(b) for b in mac_bytes])

def get_mac_vendor(mac_addr):
    global MAC_CACHE
    MAC_URL = 'http://macvendors.co/api/%s'
    mac_prefix = mac_addr[:8]
    if mac_prefix in MAC_CACHE:
        return MAC_CACHE[mac_prefix]
    try:
        req = requests.get(MAC_URL % mac_addr).json()['result']
    except:
        req = None
    try:
        mac_vendor = req['company']
    except:
        mac_vendor = '?'
    MAC_CACHE[mac_prefix] = mac_vendor
    return mac_vendor

for packet in packets:
    if DHCP in packet:
        count += 1
        print('[%d] DHCP packet detected!' % (count))
        mac_addr = ':'.join(['{:02x}'.format(b) for b in packet[BOOTP].chaddr[:6]])
        message_type = 0
        hostname = ''
        req_addr = ''
        for option in packet[DHCP].options:
            if option[0] == 'message-type':
                message_type = option[1]
            elif option[0] == 'hostname' and not hostname:
                hostname = option[1].decode()
            elif option[0] == 81 and not hostname:
                hostname = option[1][3:].decode()
            elif option[0] == 'requested_addr':
                req_addr = option[1]
        if message_type == 4: # decline
            continue
        if mac_addr not in profiles:
            profiles[mac_addr] = {
                'hostname': hostname,
                'req_addr': [req_addr],
                'mac_company': '',
                'discover_count': 0
            }
        if hostname and not profiles[mac_addr]['hostname']:
            profiles[mac_addr]['hostname'] = hostname
        if message_type == 1: # discover
            profiles[mac_addr]['discover_count'] += 1
        if req_addr:
            profiles[mac_addr]['req_addr'].append(req_addr)
        profiles[mac_addr]['mac_company'] = get_mac_vendor(mac_addr)
    if ARP in packet:
        arp = packet[ARP]
        if arp.op == 2: # reply
            if arp.psrc not in arp_stat:
                arp_stat[arp.psrc] = {}
            if arp.hwsrc not in arp_stat[arp.psrc]:
                arp_stat[arp.psrc][arp.hwsrc] = {
                    'count': 0,
                    'company': get_mac_vendor(arp.hwsrc)
                }
            arp_stat[arp.psrc][arp.hwsrc]['count'] += 1


duration = packets[len(packets)-1].time - packets[0].time

sorted_profiles = sorted(profiles.items(), key=lambda item: item[1]['discover_count'], reverse=True)

print('\n[ DHCP Starvation ]')

idx = 0
for p in sorted_profiles:
    idx += 1
    print('[%d] "%s" (%s by %s) sent %d discoveries (%f/s), and requested %d IPs.' % (idx, p[1]['hostname'], p[0], p[1]['mac_company'], p[1]['discover_count'], p[1]['discover_count']/duration, len(p[1]['req_addr'])))

print('\n[ ARP Spoofing ]')
for ip_addr in arp_stat.keys():
    if len(arp_stat[ip_addr].keys()) > 1:
        print('[i] %s has %d mac addresses:' % (ip_addr, len(arp_stat[ip_addr].keys())))
        for mac in arp_stat[ip_addr].keys():
            print('    %s (%s): %d times' % (mac, arp_stat[ip_addr][mac]['company'], arp_stat[ip_addr][mac]['count']))

print('\n[i] Total duration: %fs' % (duration))