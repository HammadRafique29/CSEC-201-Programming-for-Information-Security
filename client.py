from cryptography.hazmat.primitives.ciphers import Cipher
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import json
import os
import time

# Define a ChatbotClient class for handling communication with the server
class ChatbotClient:
    def __init__(self, host, port):
        # Initialize the client with host, port, a socket, and a random 8-byte key
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        self.key = get_random_bytes(8)

    def send_packet(self, packet):
        # Send a packet to the server
        self.client_socket.send(packet.encode())
    
    def receive_packet(self):
        # Receive a packet from the server
        return self.client_socket.recv(1024).decode()
    
    def encrypt_message(self, message, key):
        # Encrypt a message using the DES algorithm
        cipher = DES.new(key, DES.MODE_ECB)
        padded_message = pad(message.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    def decrypt_message(self, ciphertext, key):
        # Decrypt a ciphertext using the DES algorithm
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_message = cipher.decrypt(ciphertext)
        unpadded_message = unpad(decrypted_message, DES.block_size)
        return unpadded_message.decode('utf-8')

    def unsecuredCommunication(self):
        # Perform non-secured communication with the server
        self.send_packet('{"PacketType": "SS", "ProtocolName":"TTP", "ProtocolVersion":"v1.0", "CommunicationType":"0"}')
        confirm_connection_packet = client.receive_packet()
        print(confirm_connection_packet)
        self.SendMessages()
    
    def securedCommunication(self, comType):
        # Perform secured communication based on the specified communication type
        if comType.lower() == "des":
            # For DES communication, send key and receive a session key from the server
            self.send_packet('{"PacketType": "SS", "ProtocolName":"TTP", "ProtocolVersion":"v1.0", "CommunicationType":"1"}')
            confirm_connection_packet = client.receive_packet()
            
            print(self.key)
            print(f"Here is the Key {self.key}")
            packet = json.dumps({
            "PacketType": "EC",
            "Algorithm": "DES",
            "Credentials": str(self.key)
            })
            self.send_packet(packet)
            confirm_connection_packet = client.receive_packet()
            confirm_connection_packet = json.loads(confirm_connection_packet)
            self.session_key = confirm_connection_packet["SessionKey"]
            self.SendMessages(comType="normal")
            
        elif comType.lower() == "authentication":
            # For authentication, prompt user for credentials and authenticate with the server
            os.system("cls")
            print("\t\tTesting: user1:pass1")
            self.send_packet('{"PacketType": "SS", "ProtocolName":"TTP", "ProtocolVersion":"v1.0", "CommunicationType":"1"}')
            confirm_connection_packet = client.receive_packet()
  
            time.sleep(1)
            username = input("\t\tEnter Username: ")
            password = input("\t\tEnter Password: ")
            
            packet = json.dumps({
            "PacketType": "EC",
            "Algorithm": "Authentication",
            "ProtocolVersion":"v1.0",
            "CommunicationType":"1",
            "Credentials": "{0}:{1}".format(username, password)
            })
            self.send_packet(str(packet))
            
            confirm_connection_packet = client.receive_packet()
            confirm_connection_packet = json.loads(confirm_connection_packet)
            print("\t\t", confirm_connection_packet["PacketType"])
            if confirm_connection_packet["PacketType"] == "CC":
                print("\t\tConnection Successful")
                self.SendMessages()
            else: 
                print("\t\tConnection Failed. Try Again")
                time.sleep(2)
                return 0
            
    def SendMessages(self, comType="normal"):
        # Send messages to the server
        os.system("cls")
        
        messages = [
            "Hello, how are you?",
            "What is the time now?",
            "Search for Python tutorials",
            "Grant permission for access"]
        
        while True:
            
            print(f"\t{'#'*50}")
            print(f"\t{'#'*5}\t\t\tMessages\t    {'#'*5}")
            print(f"\t{'#'*50}\n")
        
            print(f"\t\t{messages[0]}")
            print(f"\t\t{messages[1]}")
            print(f"\t\t{messages[2]}")
            print(f"\t\t{messages[3]}")
            print(f"\t\tType 5 for Closing Message")
            print(f"\t\tType 6 for Exit\n")
            
            mess = input("\t\tEnter your message: ")
            if mess == "6":
                break
            elif mess.lower() == "5":
                # Send a closing message to the server
                self.send_packet('{"PacketType": "ED", "Message":""}')
                response_packet = client.receive_packet()
                print("\t\t", response_packet)
                time.sleep(1)
                break
                
            else:
                packet = json.dumps({
                    "PacketType": "IN",
                    "Message": mess,
                })
                
                if comType == "des": packet = self.encrypt_message(str(packet), self.key)
                self.send_packet(str(packet))
                
                response_packet = client.receive_packet()
                
                if comType == "des": 
                    response_packet = response_packet.replace('\\\\', '\\')
                    response_packet = response_packet[2:-1].encode('utf-8').decode('unicode_escape').encode("raw_unicode_escape")
                    response_packet = self.decrypt_message(response_packet, self.key)
                    
                print(f"\t\t{response_packet}")
                time.sleep(2)
                os.system("cls")
            
    def close_connection(self):
        # Close the client socket
        self.client_socket.close()

if __name__ == "__main__":


    while True:
        client = ChatbotClient('127.0.0.1', 12345)
        os.system("cls")
        
        print(f"\t{'#'*50}")
        print(f"\t{'#'*5}\t\t\tWelcome\t\t    {'#'*5}")
        print(f"\t{'#'*50}\n")
        
        print("\t\t1: Non Secured Communication: ")
        print("\t\t2: Secured Authentication Communication: ")
        print("\t\t3: Secured DES Communication: ")
        print("\t\t4: Exit: ")
        choice = int(input("\t\tConnectType: "))
        
        match choice:
            case 1:
                client.unsecuredCommunication()
                client.close_connection()
            case 2:
                client.securedCommunication("authentication")
                client.close_connection()
            case 3:
                client.securedCommunication("des")
                client.close_connection()
            case 4:
                client.close_connection()
                break
    
    client.close_connection()
