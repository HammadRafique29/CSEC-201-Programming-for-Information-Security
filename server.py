from cryptography.hazmat.primitives.ciphers import Cipher
import socket
import json
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class ChatbotServer:    
    def __init__(self, host, port):
        # Initialize ChatbotServer with host and port
        self.host = host
        self.port = port
        self.Initialize()  # Call the initialization method
        self.session_key = None

    def Initialize(self):
        # Initialize the server socket and basic configurations
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")
        self.Authentications = ["user1:pass1", "user2:pass2"]  # List of user credentials
    
    def encrypt_message(self, message, key):
        # Encrypt the message using the DES algorithm
        cipher = DES.new(key, DES.MODE_ECB)
        padded_message = pad(message.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext
    
    def decrypt_message(self, ciphertext, key):
        # Decrypt the ciphertext using the DES algorithm
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_message = cipher.decrypt(ciphertext)
        unpadded_message = unpad(decrypted_message, DES.block_size)
        return unpadded_message.decode('utf-8')
        
    def handle_client(self, client_socket):
        # Handle incoming client connections
        Data = client_socket.recv(1024).decode()
        Data = json.loads(Data)
        PacketType = Data["PacketType"]
        self.Startpacket(client_socket, Data)
        
    def Startpacket(self, client_socket, Data):
        # Start processing packets based on the communication type
        communicationType = int(Data["CommunicationType"])
        comType = "normal"
        if communicationType == 0:
            # Send a greeting for communicationType 0
            client_socket.send("Hi, Gotch You".encode())
        elif communicationType == 1:
            # Inform the client about waiting for authentications
            client_socket.send("Waiting For Authentications".encode())
            # Process the EncryptionPacket and set the communication type
            result = self.EncryptionPacket(client_socket, Data)
            if not result: return False 
            else: comType = result
        
        self.InformationPackets(client_socket, comType)
    
    def InformationPackets(self, client_socket, comType="normal"):
        while True:
            # try:
            information_packet = client_socket.recv(1024).decode()
            if comType == "des":
                print(information_packet)
                # Process and decrypt DES-encrypted information packets
                information_packet = information_packet.replace('\\\\', '\\')
                information_packet = information_packet[2:-1]
                information_packet = information_packet.encode('utf-8').decode('unicode_escape').encode("raw_unicode_escape")
                information_packet = DecryptMessage(self.session_key, information_packet).Decrypt()
                message_type = information_packet["PacketType"]
                message_content = information_packet["Message"]
                print(information_packet)
            
            else:
                # Process JSON-formatted information packets
                information_packet = json.loads(information_packet)
                print(self.session_key)
                message_type = information_packet["PacketType"]
                message_content = information_packet["Message"]
            
            print(information_packet)

            if "hello" in message_content.lower():
                response_packet = json.dumps({"PacketType": "GR", "ResponseMessage": "Greetings!"})
            elif "what" in message_content.lower():
                response_packet = json.dumps({"PacketType": "IR", "ResponseMessage": "Information Response"})
            elif "search" in message_content.lower():
                response_packet = json.dumps({"PacketType": "RR", "ResponseMessage": "Google results: ..."})
            elif "permission" in message_content.lower():
                response_packet = json.dumps({"PacketType": "PR", "ResponseMessage": "Permission granted"})
            elif message_type == "ED":
                message = "Client has confirmed the closing phase."
                if comType == "des": information_packet = self.encrypt_message(message, self.session_key)
                client_socket.send(message.encode())
                return True
            else: response_packet = json.dumps({"PacketType": "EE", "ErrorCode": 1, "Description": "Unknown request"})
            
            client_socket.send(response_packet.encode())

    
    def EncryptionPacket(self, client_socket, Data):
        def passwordAuthentication(authentication):
            if authentication in self.Authentications: return "normal"
            else: return False
        
        def DES_Authentication(publicKey):
            # sessionKey = self.des.encrypt_session_key(client_public_key=publicKey)
            sessionKey = publicKey
            sessionKey = sessionKey.replace('\\\\', '\\')
            sessionKey = sessionKey[2:-1]
            self.session_key = sessionKey.encode().decode('unicode_escape').encode("raw_unicode_escape")
            print(self.session_key, type(self.session_key))
            
            packet = json.dumps({
                "PacketType": "SK",
                "SessionKey": f"{sessionKey}"
            })
            client_socket.send(packet.encode())
        
        Data = client_socket.recv(1024).decode()
        Data = json.loads(Data)
        if Data["Algorithm"] == "Authentication": 
            status = passwordAuthentication(Data["Credentials"])
            if not status: 
                client_socket.send(json.dumps({"PacketType": "EE", "ErrorCode": 1, "Description": "Unknown request"}).encode())
                return False
            else: 
                client_socket.send(json.dumps({"PacketType": "CC", "Description": "Authentication Successful"}).encode())
                return "normal"
        elif Data["Algorithm"] == "DES":
            DES_Authentication(Data["Credentials"]) 
            return "des"       
            
    def start(self):
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"Accepted connection from {addr}")
                # Handle the client connection
                self.handle_client(client_socket)
            except: pass

if __name__ == "__main__":
    server = ChatbotServer('127.0.0.1', 12345)
    server.start()
