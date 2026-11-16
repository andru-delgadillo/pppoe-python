import socket
from scapy.all import *
import time

# Configuración del servidor
HOST = '192.168.1.2'  # Dirección IP del cliente
IFACE = "enx7cc2c64b7b16"

with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:    
    s.bind((IFACE,0))
    
    def paso_5_client(packet):
        if (PPP in packet) and (PPP_LCP_Terminate in packet) and (packet[PPP_LCP_Terminate].code == 6):
            print("PPP/LCP/Termination Ack [Detectado]")
            print("===[ Fin de la Conexión ]===")
            exit(0)

    def paso_4_client(packet):

        if (PPP in packet) and (PPP_IPCP in packet) and (packet[PPP_IPCP].code == 2):

            print("Paquete PPP/IPCP/Configuration Ack [Detectado]")
            MAC_SERVER = packet[Ether].src
            MAC_CLIENT = packet[Ether].dst
            PAYLOAD1 = Raw(load=b"Andru")
            PAYLOAD2 = Raw(load=b"Gustavo")
            PAYLOAD3 = Raw(load=b"Eduardo")
            IP_ = IP(src="192.168.1.2", dst="192.168.1.1")
            IP_PAYLOAD1 = bytes(IP_ / PAYLOAD1)
            IP_PAYLOAD2 = bytes(IP_ / PAYLOAD2)
            IP_PAYLOAD3 = bytes(IP_ / PAYLOAD3)
            PPP_ = struct.pack("!H", 0x0021)
            PPPOE_1 = struct.pack("!BBHH", 0x11, 0x00, 0x0001, len(PPP_ + IP_PAYLOAD1))
            PPPOE_2 = struct.pack("!BBHH", 0x11, 0x00, 0x0001, len(PPP_ + IP_PAYLOAD2))
            PPPOE_3 = struct.pack("!BBHH", 0x11, 0x00, 0x0001, len(PPP_ + IP_PAYLOAD3))
            ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_SERVER.replace(':', '')),bytes.fromhex(MAC_CLIENT.replace(':', '')),0x8864)
            PPP_IP_PAYLOAD1 = ETHER_ + PPPOE_1 + PPP_ + IP_PAYLOAD1
            PPP_IP_PAYLOAD2 = ETHER_ + PPPOE_2 + PPP_ + IP_PAYLOAD2
            PPP_IP_PAYLOAD3 = ETHER_ + PPPOE_3 + PPP_ + IP_PAYLOAD3
            time.sleep(1)
            s.send(bytes(PPP_IP_PAYLOAD1))
            time.sleep(1)
            s.send(bytes(PPP_IP_PAYLOAD2))
            time.sleep(1)
            s.send(bytes(PPP_IP_PAYLOAD3))
            print("Paquetes con Nombres [Enviados]")
            ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_SERVER.replace(':', '')),bytes.fromhex(MAC_CLIENT.replace(':', '')),0x8864)
            PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,12)
            PPP_ = struct.pack('!H',0xc021)
            LCP_TERMINATION_REQUEST = bytes([0x05,0x01,0x00,0x0a,0x03,0x04,0xc0,0x23,0x05,0x06])
            PPP_LCP_TERMINATION_REQUEST = ETHER_ + PPPOE_ + PPP_ + LCP_TERMINATION_REQUEST
            time.sleep(2)
            s.send(bytes(PPP_LCP_TERMINATION_REQUEST))
            print("PPP/LCP/Termination Request [Enviado]")
            sniff(prn=paso_5_client, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")

    def paso_3_client(packet):

        if (PPP in packet) and (PPP_PAP_Response in packet) and (packet[PPP_PAP_Response].code == 2): #PPP/PAP/AUTHENTICATE-ACK

            print("Paquete PPP/PAP/Authenticate-ACK [Detectado], Usuario y Contraseña [Correctos]")
            MAC_SERVER = packet[Ether].src
            MAC_CLIENT = packet[Ether].dst
            ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_SERVER.replace(':', '')),bytes.fromhex(MAC_CLIENT.replace(':', '')),0x8864)
            PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,0x18)
            PPP_ = struct.pack('!H',0x8021)
            IPCP_ = bytes([0x01,0x01,0x00,0x16,0x03,0x06,0x00,0x00,0x00,0x00,129,0x06,0x00,0x00,0x00,0x00,131,0x06,0x00,0x00,0x00,0x00])
            PPP_IPCP_CONFIGURATION_REQUEST = ETHER_ + PPPOE_ + PPP_ + IPCP_
            time.sleep(2)
            s.send(bytes(PPP_IPCP_CONFIGURATION_REQUEST))
            print("PPP/IPCP/Configuration Request [Enviado]")
            sniff(prn=paso_4_client, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")

        if (PPP in packet) and (PPP_PAP_Response in packet) and (packet[PPP_PAP_Response].code == 3): #PPP/PAP/Authenticate-NACK

            print("Paquete PPP/PAP/Authenticate-NACK [Detectado], Usuario o Contraseña [Incorrectos]")
            print("===[ Fin de la Conexión ]===")
            exit(0)

    def paso_2_client(packet):

        if (PPP in packet) and (PPP_LCP_Configure in packet) and (packet[PPP_LCP_Configure].code == 2): #PPP/LCP/Configuration Ack

            print("Paquete PPP/LCP/Configuration Ack [Detectado]")
            print("Conexión Establecida")
            MAC_SERVER = packet[Ether].src
            MAC_CLIENT = packet[Ether].dst
            username = input("Username: ")
            password = input("Password: ")
            ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_SERVER.replace(':', '')),bytes.fromhex(MAC_CLIENT.replace(':', '')),0x8864)
            PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,16)
            PPP_ = struct.pack('!H',0xc023)
            PAP_AUTHENTICATION_REQUEST_ = bytes([0x01,0x01,0x00,0x0d])+bytes([len(username)])+username.encode()+bytes([len(password)])+password.encode()
            PPP_PAP_AUTHENTICATION_REQUEST = ETHER_ + PPPOE_ + PPP_ + PAP_AUTHENTICATION_REQUEST_
            time.sleep(2)
            s.send(bytes(PPP_PAP_AUTHENTICATION_REQUEST))
            print("PPP/PAP/Authentication Request [Enviado]")
            sniff(prn=paso_3_client, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")

    def paso_1_client():

        MAC_CLIENT = get_if_hwaddr(IFACE)
        MAC_SERVER = "ff:ff:ff:ff:ff:ff"
        ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_SERVER.replace(':', '')),bytes.fromhex(MAC_CLIENT.replace(':', '')),0x8864)
        PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,12)
        PPP_ = struct.pack('!H',0xc021)
        LCP_CONFIGURE_REQUEST_ = bytes([0x01,0x01,0x00,0x0a,0x03,0x04,0xc0,0x23,0x05,0x06])
        PPP_LCP_CONFIGURE_REQUEST = ETHER_ + PPPOE_ + PPP_ + LCP_CONFIGURE_REQUEST_ # Discovery Packet
        time.sleep(1)
        s.send(bytes(PPP_LCP_CONFIGURE_REQUEST))
        print("PPP/LCP/Configuration Request [Enviado]")
        sniff(prn=paso_2_client, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")
        
    paso_1_client()

    


