from scapy.all import *
import os
from OTXv2 import OTXv2
import IndicatorTypes
import requests
import json

#OTX URL Address
OTX_SERVER = 'https://otx.alienvault.com/'
#Your OTX API ket. By default you can search for 10K requests per hour.
API_KEY = 'Your OTX Api key'
otx = OTXv2(API_KEY,server=OTX_SERVER)

#PCap file that you need to analyse.
packets=rdpcap('PCAP file path')
#Virus total url and header info.Give your VT API key.
vt_url = "https://www.virustotal.com/api/v3/ip_addresses/"
vt_headers = {
    "Accept": "application/json",
    "x-apikey": "Your VT API key"
}
def create_files(srcIPs):

    text_file = open(srcIPs,'w')
    for packet_number in range(len(packets)):
            packet = packets[packet_number]
            try:
                text_file.writelines(packet['IP'].src+'\n')
                text_file.writelines(packet['IP'].dst+'\n')
            except:
                print()
    remove_duplication()
def remove_duplication():
    rersult = open(path_new, 'r')
    newfile=path+'\dedup_ips.txt'
    out_file = open(newfile,'w')
    uniqline = set(rersult.readlines())
    out_file.writelines(set(uniqline))
    out_file.close()
    rersult.close()
    ip_details(otx,newfile)
def ip_details(otx,newfile):
 ips=open(newfile,'r')
 for ip in ips.readlines():
    ip=ip.rstrip("\n")
    vt_verdict(ip)
    try:
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        count=result['pulse_info']['count']
        otx_verdict(count,ip)
    except Exception as e:
        print(e)
def otx_verdict(count,ip):
    alerts=int(count)
    if alerts >0:
            print(ip+'-----'+' Found malicious in OTX  ---'+'Pulses Count is :' + str(count))
def vt_verdict(ip):
    vt_response = requests.request("GET", vt_url + ip.rstrip(), headers=vt_headers)
    a = vt_response.json()
    try:
        z = a['data']['attributes']['last_analysis_stats']
        if (z['malicious'] > 3 or z['suspicious'] > 1):
            print(ip.rstrip() + '  is malicious')
        else:
            print("IP not Malicious")
    except:
        print('IP not found')

if __name__ == '__main__':
    path = input('Enter Valid Path to store IPs:')
    path_new = path + '\IPs.txt'
    if (os.path.exists(path)):
        create_files(path_new)
    else:
        print('Path is incorrect please re-run and enter again!')
    os.remove(path_new)



