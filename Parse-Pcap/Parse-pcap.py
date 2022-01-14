from scapy.all import *
import xlsxwriter
import os
import argparse
from OTXv2 import OTXv2
import IndicatorTypes
import requests
import sys
''' Description: This script is created to get online reputation of IPs from VT and OTX. you may provide list of ips in text or a pcap file.
Author : Majid Jahangeer
Version: 1.1'''
#OTX URL Address
OTX_SERVER = 'https://otx.alienvault.com/'
#Your OTX API ket. By default you can search for 10K requests per hour.
API_KEY = 'OTX API key'
otx = OTXv2(API_KEY,server=OTX_SERVER)
#Virus total url and header info.Give your VT API key.
vt_url = "https://www.virustotal.com/api/v3/ip_addresses/"
vt_headers = {
    "Accept": "application/json",
    "x-apikey": "Virus total api key"
}
row=1
def create_files(srcIPs,packets,current_path):

    text_file = open(srcIPs,'w')
    for packet_number in range(len(packets)):
            packet = packets[packet_number]
            try:
                text_file.writelines(packet['IP'].src+'\n')
                text_file.writelines(packet['IP'].dst+'\n')
            except:
                print()
    remove_duplication(srcIPs,current_path)
def remove_duplication(srcIPs,current_path):
    rersult = open(srcIPs, 'r')
    newfile=current_path+'\dedup_ips.txt'
    out_file = open(newfile,'w')
    uniqline = set(rersult.readlines())
    for unique_ip in uniqline:
        #Regex to remove private ip addresses
        if (re.match(
                "(?!(10)|192\.168|172\.(2[0-9]|1[6-9]|3[0-1])|(25[6-9]|2[6-9][0-9]|[3-9][0-9][0-9]|99[1-9]))[0-9]{1,3}\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                unique_ip.rstrip())):
            out_file.writelines(unique_ip)
    out_file.close()
    rersult.close()
    ip_details(otx,newfile)
def ip_list(iplist):
    ip_details(otx,iplist)

def ip_details(otx,newfile):
 global row
 try:
    ips=open(newfile,'r')
    for ip in ips.readlines():
        ip=ip.rstrip("\n")
        vt_verdict(ip)
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        count=result['pulse_info']['count']
        otx_verdict(count,ip)
        row+=1
 except Exception as e:
     print(str(e)+ ' Please Provide valid IP list in text file.')
def otx_verdict(count,ip):
    alerts=int(count)
    if alerts >0:
        write_worksheet(ip,alerts)
def vt_verdict(ip):
    vt_response = requests.request("GET", vt_url + ip.rstrip(), headers=vt_headers)
    a = vt_response.json()
    try:
        z = a['data']['attributes']['last_analysis_stats']
        worksheet.write(row,1,z['malicious'])
        worksheet.write(row,2,z['suspicious'])
    except Exception as e:
        print(e)
def create_worksheet(outfile):
    c_col = 0
    outfile.set_column('A:F', 30)
    list = ['IP', 'VT_Malicious_Count', 'VT_Suspicious_Count', 'OTX Pulse Count']
    for values in list:
        outfile.write(0,c_col,values)
        c_col=c_col+1
def write_worksheet(ip,alerts):

    worksheet.write(row,0,ip)
    worksheet.write(row,3,alerts)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', dest='input_file', action="store")
    parser.add_argument('-m', '--mode', dest='mode', action="store",help= '-m PCAP ')
    parser.add_argument('-o', '--output', dest='output_file', action='store')
    args = parser.parse_args()
    current_path = os.getcwd()
    pcap_output = current_path + '\IPs.txt'
    workbook=xlsxwriter.Workbook(args.output_file)
    worksheet=workbook.add_worksheet()
    if ((len(sys.argv[1:])) == 6 and args.mode.upper()) == 'TEXT':
        create_worksheet(worksheet)
        ip_list(args.input_file)
    elif ((len(sys.argv[1:])) == 6 and args.mode.upper()) == 'PCAP':
        try:
            create_worksheet(worksheet)
            packets = rdpcap(args.input_file)
            create_files(pcap_output, packets, current_path)
        except Exception as e:
            print(str(e) + '  Please provide valid pcap file.')
    else:
        parser.print_help()
    workbook.close()
    os.remove(pcap_output)
    os.remove(current_path+'\dedup_ips.txt')



