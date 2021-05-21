import network
import urequests as requests
import socket
import json
from machine import UART
import struct
import time
import sys
import _thread
from server import SSDPServer
#import server

AQMSERIAL = "EK12AQ000010"
DSM101 = "EJ12DS000030"
SERVICE_PORT = 8812
SSID = 'NEXT-7004N'
PW = '@123456789a'
SSID = 'kictech_a2004mu'
PW = 'qkfmsrltnf'

def do_connect():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    print('wlan : ',wlan)
    if not wlan.isconnected():
        print('connecting to network...')
        wlan.connect(SSID,PW)
        print('wlan.isconnected() : ',wlan.isconnected())
        while not wlan.isconnected():
            pass
    print("wlan.ifconfig: ",wlan.ifconfig())
    print("do_connect success")


def post_device_information(go_server_url):
    go_server_url = go_server_url + "/api/devices"
    data = json.dumps({"aqman_serial":AQMSERIAL,"dsm_serial":DSM101, "fw_version":"V1.02A"})
    res = requests.post(go_server_url, data=data)

def parse_network_data(t):
    d = {}
    d["ip"] = t[0]
    d["netmask"] = t[1]
    d["gateway"] = t[2]
    d["nameserver"] = t[3]
    d["sn"] = AQMSERIAL
    d["port"] = str(SERVICE_PORT)
    print("parse_network_data : ",d)
    return d

def post_network_data(go_server_url):
    print("come into post_network_data")
    go_server_url = go_server_url + "/api/device/" + AQMSERIAL
    print("go_server_url: ",go_server_url)
    wlan = network.WLAN(network.STA_IF)
    print("post_network_data: ",wlan)
    wlan.active(True)
    if wlan.isconnected():
        data = parse_network_data(wlan.ifconfig())
    data = json.dumps(data)
    print("data of post_network_data: ",data)
    print("go_server_url: ",go_server_url)
    res = requests.request(method="POST", url=go_server_url, data=data) #If db doesn't have a value, it won't succeed.
    print("post request success")

def get_network_data():
    wlan = network.WLAN(network.STA_IF)
    print("post_network_data: ",wlan)
    wlan.active(True)
    if wlan.isconnected():
        data = parse_network_data(wlan.ifconfig())
        #data = json.dumps(data)
    
    return data
    
def get_sensor_data(uart):
    request_bytes = b'\x02\xac\x00\x00\x53'
    uart.write(request_bytes)
    buffer = bytearray(33)
    uart.readinto(buffer)
    return buffer

def parse_sensor_data(buffer):
    data = struct.unpack('33B', buffer)
    d = {}
    d["sn"] = AQMSERIAL #static value
    d["dsm101_sn"] = DSM101 #static value
    d["radon"] = int.from_bytes(buffer[6:8], 'little')
    d["pm1"] = int.from_bytes(buffer[8:10], 'little')
    d["pm2d5"] = int.from_bytes(buffer[10:12], 'little')
    d["pm10"] = int.from_bytes(buffer[12:14], 'little')
    d["co2"] = int.from_bytes(buffer[14:16], 'little')
    d["tvoc"] = int.from_bytes(buffer[26:28], 'little')
    d["temp"] = float("{:.2f}".format(struct.unpack('f',buffer[18:22])[0]))
    d["humi"] = float("{:.2f}".format(struct.unpack('f',buffer[22:26])[0]))
    return d

def server(uart):
    addr = socket.getaddrinfo('0.0.0.0', SERVICE_PORT)[0][-1]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("before s.bind(addr)")
    s.bind(addr)
    print("before s.listen(5)")
    s.listen(5)
    print('listening on', addr)
    while True:
        conn, addr = s.accept()
        print('client connected from', addr)
        
        request = conn.recv(1024)
        if request:
            raw = get_sensor_data(uart)
            response = parse_sensor_data(raw)
        
            conn.send('HTTP/1.1 200 OK\n')
            conn.send('Content-Type: application/json\n')
            conn.send('Connection: close\n\n')
            print(response)
            conn.sendall(json.dumps(response))
            conn.close()

def ssdp_server_Threading(network_data,port):
    print("@@@@@@@@@@@@ssdp_server_Threading started!@@@@@@@@@@@@@@")
    ssdp_response_server = SSDPServer(usn = "hass-aqman-server", device_type = "ssdp:kictechaqman", location= network_data)
    ssdp_response_server.serve_forever()

def uart_server_Threading():
    print("@@@@@@@@@@@Initializing UART connection@@@@@@@@@@@@@@")
    uart = UART(1, 19200)
    uart.init(baudrate=19200,timeout=1000, tx=17,rx=16)
    server(uart)
    

if __name__ == '__main__':
    # Connect to Wi-Fi
    print("Connecting to Wifi...")
    do_connect()  
    
    network_data_temp = get_network_data()
    print("ip_address_temp :{0}".format(network_data_temp))
    
    ip_address = network_data_temp['ip']
    print("####ip_address: #####",ip_address)

    port = '8297'
    _thread.start_new_thread(ssdp_server_Threading,(network_data_temp,port))
    _thread.start_new_thread(uart_server_Threading,())


