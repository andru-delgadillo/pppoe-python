import socket
from scapy.all import *
import time

# Configuración del servidor
HOST = '192.168.1.1'  # Dirección IP del servidor
IFACE = 'enp3s0'
USERNAME = "redes"
PASSWORD = "123"

# Crear socket
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
    s.bind((IFACE,0))
    print("Socket creado y vinculado a la interfaz:", IFACE)

    def paso_4_server(packet):

        if (PPP in packet):

            if (Raw in packet):

                payload = packet[Raw].load
                payload = payload.decode('utf-8')
                print(payload)

            if (PPP_LCP_Terminate in packet) and (packet[PPP_LCP_Terminate].code == 5): #PPP/LCP/TERMINATION REQUEST

                print("Paquete PPP/LCP/Termination Request [Detectado]")
                MAC_CLIENT = packet[Ether].src
                MAC_SERVER = packet[Ether].dst
                ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_CLIENT.replace(':', '')),bytes.fromhex(MAC_SERVER.replace(':', '')),0x8864)
                PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,12)
                PPP_ = struct.pack('!H',0xc021)
                LCP_TERMINATION_ACK = bytes([0x06,0x01,0x00,0x0a,0x03,0x04,0xc0,0x23,0x05,0x06])
                PPP_LCP_TERMINATION_ACK = ETHER_ + PPPOE_ + PPP_ + LCP_TERMINATION_ACK
                time.sleep(2)
                s.send(bytes(PPP_LCP_TERMINATION_ACK))
                print("PPP/LCP/Termination Ack [Enviado]")
                print("===[ Fin de la Conexión ]===")
                exit(0)
    
    def paso_3_server(packet):

        if (PPP in packet) and (PPP_IPCP in packet) and (packet[PPP_IPCP].code == 1): #PPP/IPCP/CONFIGURATION-REQUEST
            
            print("Paquete PPP/IPCP/Configuration Request [Detectado]")
            MAC_CLIENT = packet[Ether].src
            MAC_SERVER = packet[Ether].dst                
            ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_CLIENT.replace(':', '')),bytes.fromhex(MAC_SERVER.replace(':', '')),0x8864)
            PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,0x18)
            PPP_ = struct.pack('!H',0x8021)
            IPCP_ = bytes([0x02,0x01,0x00,0x16,0x03,0x06,0x00,0x00,0x00,0x00,129,0x06,0x00,0x00,0x00,0x00,131,0x06,0x00,0x00,0x00,0x00])
            PPP_IPCP_CONFIGURATION_ACK = ETHER_ + PPPOE_ + PPP_ + IPCP_
            time.sleep(2)
            s.send(bytes(PPP_IPCP_CONFIGURATION_ACK))
            print("PPP/LCP/Configuration Ack [Enviado]")
            sniff(prn=paso_4_server, store=False, iface=IFACE, count=4, filter="ether proto 0x8864") #CUATRO PAQUETES 3 NOMBRES Y UNO TERMINATE REQUEST

    def paso_2_server(packet):

        if (PPP in packet) and (PPP_PAP_Request in packet) and (packet[PPP_PAP_Request].code == 1): #PPP/PAP/Authenticate Request
            
            print("Paquete PPP/PAP/Authenticate Request [Detectado]")
            extractedUser = packet[PPP_PAP_Request].username
            extractedUser = extractedUser.decode('utf-8')
            extractedPass = packet[PPP_PAP_Request].password
            extractedPass = extractedPass.decode('utf-8')

            MAC_CLIENT = packet[Ether].src
            MAC_SERVER = packet[Ether].dst

            if extractedUser == USERNAME and extractedPass == PASSWORD:

                print("Usuario y Contraseña [Correctos]")
                ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_CLIENT.replace(':', '')),bytes.fromhex(MAC_SERVER.replace(':', '')),0x8864)
                PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,0x07)
                PPP_ = struct.pack('!H',0xc023)
                PAP_AUTHENTICATE_ACK_ = bytes([0x02,0x01,0x00,0x05,0x00])
                PPP_PAP_AUTHENTICATE_ACK = ETHER_ + PPPOE_ + PPP_ + PAP_AUTHENTICATE_ACK_
                time.sleep(2)
                s.send(bytes(PPP_PAP_AUTHENTICATE_ACK))
                print("PPP/PAP/Authenticate-ACK [Enviado]")
                sniff(prn=paso_3_server, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")
                
            else:
                
                ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_CLIENT.replace(':', '')),bytes.fromhex(MAC_SERVER.replace(':', '')),0x8864)
                PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,0x07)
                PPP_ = struct.pack('!H',0xc023)
                PAP_AUTHENTICATE_NACK_ = bytes([0x03,0x01,0x00,0x05,0x00])
                PPP_PAP_AUTHENTICATE_NACK = ETHER_ + PPPOE_ + PPP_ + PAP_AUTHENTICATE_NACK_
                time.sleep(2)
                s.send(bytes(PPP_PAP_AUTHENTICATE_NACK))
                print("Usuario o contraseña [Incorrectos]")
                print("PPP/PAP/Authenticate-NAK [Enviado]")
                print("===[ Fin de la Conexión ]===")
                exit(0)

    
    def paso_1_server(packet):

        if (PPP_LCP_Configure in packet) and (packet[PPP_LCP_Configure].code == 1): #Si el packete es PPP/LCP/Configuration Request

            print("Paquete PPP/LCP/Configuration Request [Detectado]")
            MAC_CLIENT = packet[Ether].src
            MAC_SERVER = get_if_hwaddr(IFACE)
            print("Conexion Establecida con", MAC_CLIENT)
            ETHER_ = struct.pack('!6s6sH',bytes.fromhex(MAC_CLIENT.replace(':', '')),bytes.fromhex(MAC_SERVER.replace(':', '')),0x8864)
            PPPOE_ = struct.pack('!BBHH',0x11,0x00,0x0001,12)
            PPP_ = struct.pack('!H',0xc021)
            LCP_CONFIGURATION_ACK_ = bytes([0x02,0x01,0x00,0x0a,0x03,0x04,0xc0,0x23,0x05,0x06])
            PPP_LCP_CONFIGURATION_ACK = ETHER_ + PPPOE_ + PPP_ + LCP_CONFIGURATION_ACK_
            time.sleep(2)
            s.send(bytes(PPP_LCP_CONFIGURATION_ACK))
            print("PPP/LCP/Configuration Ack [Enviado]")
            sniff(prn=paso_2_server, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")
            

    print("Esperando Conexiones")
    sniff(prn=paso_1_server, store=False, iface=IFACE, count=1, filter="ether proto 0x8864")