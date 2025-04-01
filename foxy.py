from time          import sleep
from threading     import Thread

import re
import socket
import threading
import select
import requests
print("works")





SOCKS_VERSION = 5
data_join=b''
op=None
squad = False
hide=None
class Proxy:
    def __init__(self):
        self.username = "FOXY"
        self.password = "BOT"
        ##NEWS
        self.Sqd_Fox = False
        self.Visible_Fox = False
        self.Profile_Fox = False
        ##
        self.spam_level=False
        self.spam_chat= False
        self.botcomendenable=False
        self.inviteB = False
        self.back=False
        self.spy = False
        self.BackSpam_ip=None
        self.spamantikick=False
        self.command=False
        self.MenaServer=False
        self.LVL=False
        self.Like=False
        t = threading.Thread(target=self.udp_server)
        t.start()
        self.__list_ = [
            b'\x12\x15\x00\x00\x00\xb0\xddt\xa5\xe5;\xf4\'\x02M\xd0G\x83\\\xa5\x8ew\x03\x84\x13O\xef\xcb\x02\xe4-\x86\x0eZ\x92\xbb\x9b\xa6\x9f\xc1S\xd0\xb2S;\xa0{\xcb8\n\xe0+e+4\xc4l\xf8\xea+\x15\xbe\nW\x9d\x08W\x86ky\x9a\xd1\x96\x0e\xa7\x03\xa8\xf6\x97"\x1b/\xf8\xd3\x13\xd0\x06\xf9Y\xf6]\xe3dA\xf7\xd8X\xaf(N\xf1\x9c\x99\xffJ\x13\xde\xe6]%w\x0f#\x00\'_\x8c\xc3^\xb5K|\x0f\xe9r\xa4L\xdb-\xfd\xebD\x1b\xf1B_\xe7\x0eY\xfai\xfd\x97&\xd1gb\xe3*\x171\xbe\xf2^\x13\xf3\xa4\xa7tf\xcb\x97*\xa3a\xe5\xe4JSg\xaab/\x1e\xb1\rb\xd6\x03]l\x88'
            ,
            b"\x12\x15\x00\x00\x00\x80\x13q,\xe8]9\x8a\xd1us'\xc0p\x91v\xdb\x13\xe4\x06\x7f8<0\xe9\xf3\xfb@L\xdf\xe0)K:)p\xdf\xe7\xc3\x15A\xdcH*s5\x15\x19\x89m\x8a\xa4\xce\xc1\x84\x83\x82\xc6\xdb\x85\x1cC-[\xd6\xfap\xcd\xdf\x1b\x1f-\x19t\xb1\x198\xf5>\xead\xd7\x1c7\xd2\x12\xb92\x12\xa1V\xed\x83\x0c\xf9z\x0c\x91{\xd5B\xee1\xd8o\x0b};D\xdc\xb3\x85\xfd?i\x88\xfc]\xbf\x0c\xdcO\xb0tl\xf7\x85\xe9\xa1"
            ,
            b'\x12\x15\x00\x00\x00pT\xea9\x7f\x1f\xcfk\x8d0M\x05\xd8( \xd8\x16\xacN\x01\xbc\xb6\x87\x9b\x9f\xdc\xaff\x0b\x08\xd6\xcd\xddO3\xf2\xcfn\xc9\xa0\x00KDp}v\xdb]\xb4R\xa9.\x0f \x88\xaeK\x8e\xb5Xs\xb9g\xf2#\xfct\x8e\x1c\xc2\x1f\xc1\xd6\x1a\x93\x17\xd4s\x97O\xa5\xe2\xb3\xc8*+\xf8\xda&j\xd8\x85m\x8e\x1b\xfcF\xae\xf5f\n\xd7)n9\xbcE\xa0\x9dW\xd1\xb4\xbd'
            ,
            b'\x12\x15\x00\x00\x00p\x93W\x97\x84-\xf3\xe3\x15\x1d\xd9O)o\xbd\xd5ui\xed\x16\xe8\xc3\xd6_\xf9E\x87\x8f\x85\xad9^i1\x8c\x17\xfa\x94\xb9\xf0\x8c5A\xc8\x9brU\xee\x8d\xac\x10\x99[\x1c\x03@\xdb\x82pwaN\x11\xd4\xbe\xb7\xab\x0e\xa9y4\x80Y\x17\xaeY\x99\xd6\x12\xc2\xf0\x80\x98\x9d\xc2$\x18B\x1c\xe9\x0c5;\xde\x02R\xd5BE\xff\xd7\x1a\x06ng\xb0\xa9\xa5+\xe6|T%'
            ,
            b'\x12\x15\x00\x00\x00\x80[\x1e\x0e\x02\x12\xd9\xac\xac\x00\xd7\xa2\x9eg\x1c|s\xd6+\x984\x14\x86\xb3;\xae\x90\x94\x9e\x99[\x8aN]\x06?3\xd1jR\x99\x0cfd\xdb>sVnc\xd5\x9a\xf6\xfd<\xe3\xa9\x87\xeek\xcd\xa4\x9a\xf6\x19\x89G\xb6\xd3\x8d\xdeJ\xa5\xea\x915\xb0M<\x83\x12\x00Q\t.\x99\x08\x16\xff\n\x939F\x8e\xd5\xc16iNX\x02k{\xaf\xb9\xde\x07\x99d\x11_\x02j\xc6=\xd75e\x8du\x1e\xcd;R\xfd)\xb5\x96H'
            ,
            b"\x12\x15\x00\x00\x00\x80\xa4\xdbE\x9c\xa5V)\x04Yxr\xb6\x08\x9a\xee\x0f\xfe\xa5\xd5\xf5\xab\xa7\xc5J\xe6\x1f==\x96\xb3\xd7\x7fKh\xe4t\xecL9\x95\xa9\xd6\xc6\xed\x91$a>\xfd\xd1SFy\x920\x06\x8a:\xb8HjWI\x0e\xbf\x1abr\xb5\xa5\xc0\x94\xc4\xd9\xd9\xcb\t\xc0F\xaa\x08\xff\x96'\xd4\x07\x97H\xe3\xe4^u5\x17\xf1{lU\xe7\xb2\xb9+\xae\x001a\xad\x9c\xf6\x1aT_\x94`\x16$\xa7\x04\xd4\xe1\xe4\x00\xde\x08\x11\x82\x8dL"
            ,
            b'\x12\x15\x00\x00\x00ph\xf5\x83K\x86\xde\x85,c{\x9e?\x87\x0f\xd06\xd6.\x84"D\x9b\xa8l8\xa5\x7f\x9e\xf0\xaf\x1b\x96\x01\xc3\xa678\x1eb\xb6\xc7&J\x03\x12\x1c:s\xa8\xa20;\xc7\xb9YjK\xdc\x19\xd2#a\xf3\x87\x08\xb0\xd2"\xa2\x9bL\xbfM\xb1\xc2\xeb\x0fJ}V\xc2S\x05A\xf3snn\xf1f\xb6\x0c%\xa1dsh\x87\xc9K\x89\xb5#{/\xf12\x9fsk\xbed'
            ,
            b'\x12\x15\x00\x00\x00p\x047\xfb\xa5\\\x8b\xe8\x1f!7\x16Z\xe3\xf4I\x01\xcfV\xe9;4\xf6\xfc\x1d\xd7m8\xe6\xa2o\xbb\x0c\x03N\x1c$M\xcd\xca%\xa0\xac\xa2U\xee\xb4\x01\x82I\xc3\x0b\x80\xa7\xa0z\xf4SY\xd5\xa1P\x1d`\xaeE\x05\x87T\xd0o\x91\xeb\x0c`\xb9\xd7\x98H\x91\xca"\x93\xc33Dm\xa4\xe1"\x07}\xe1\xb5Vg\xe2=\xaa5uG\xbf\xf6\x01\x0e\x85?`\xb0\x86-\xe1'
            ,
            b"\x12\x15\x00\x00\x00\x80\x13q,\xe8]9\x8a\xd1us'\xc0p\x91v\xdb\x13\xe4\x06\x7f8<0\xe9\xf3\xfb@L\xdf\xe0)K\x9b\xedH\x8dm\xf0\xf8k\x88\xabK\xb3\\\xbc\xees\x9dS\x90\xbd\xfb\xb4\x89\xf2K\x19\t}\xc8g\n\x90\x98\xfb\xcd+`\tF$\xc3\xd2\x06\x08\xd1\xa3\xaaM5H]m\xbd\xbe\xc7\xb5\xca\xe53\xdd\xd1\xd5\xc4\xeb\x9a!\xd8\xb0\xd1,\x93-4\x16C\x99\xc6S\xba\xa3#b\xc8\xa6\xa0\xb4\xf4j\x8f\xd2\x05\x8b\x82\xa2\x8a\xd9"
            ,
            b'\x12\x15\x00\x00\x00p\xad\xd3\xc5\x1eF\xca%\x96\x06\xdaZ\x99\xc4>_\n\x81\x01]\xf8\xd2\x0b\x84\xbe\x074\\=(\x96\xb5\xa4#\xeem\xe2\x08\x06M\xe4d)\x18\xde\x96\xc2uI\xab\xe1\xcb\xd0\x17\xdc\x04\x8d\x0eF\x1b\xc2\x18Z\xd2\xc0\xb1\x9bX\x8b\x04\xdc\x12\xd8+3~\x9e\x8a\xe0\xddj%\\\xbd\x1bQX\xd6L#C\xa0\x1b\xe5\x16`\xeb]`\x98~;\x93R\x89\xe0\t\x9b \x19FC\xa3'
            ,
            b'\x12\x15\x00\x00\x00p\xdf^+\xd65_\xf4\xdb\xf2&\xec\x8d\xfc\xd2\x92\xffa\xcb\xe3\x14I\x8c\x1d\x16(\xa9\xce\xe0=\x0f\x14\x1c\xacV\xe9\xc3\xf9\x1d\xf5\xb3\xfb\xc7\xdfPp\x05d\x1b\x8c4\x86Q\x17?\xaa\x91\xd6\x99\xa3\xe0\x1b\xb4\xbf\xd8\xdd4\xa2\xf2\xbd\x83"\x86p%\x95\xd0X.\x05\xe6MN\x1c\x14\x08k\x95\xac@A|\xf1~t\xc6Ec\x8aZ\xf0\xfb\x82B\xaf\xe6\x16j\xf6\x07F\xad&'
            ,
            b"\x12\x15\x00\x00\x00p\xde\xa3\xe9fr|a\xcb\x01\xbe\xbc\x00\xc7\xc6\xea\r\x8a'\xf8\xad\xefG\x18^ko\x8aX\xe2q\xfbw\xe40\xcf\x8f\xf0\xea\xea\xb3\x9coYo\xdf)\xbac\x1c\xfcm\xd0\xc0\xdf\xdf\xdc\n^|\x1b:\xd3Fz#\x88\xe54\x972#\xdf\xef\xae8:X\xbb~\xfb\x9f\xfc\xb1\xce\x88j|\x8c\x07\xfb\x10\x88d\x1e.mu^\xe3\x13\xe7\x89V\xe6\xa8\xb3\xad\x88\xc8\xd9\x05\x8e"
        ]
    def handle_client(self, connection):
        # greeting header
        # read and unpack 2 bytes from a client
        version, nmethods = connection.recv(2)

        # get available methods [0, 1, 2]
        methods = self.get_available_methods(nmethods, connection)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            connection.close()
            return

        # send welcome message
        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection):
            return

        # request (version=5)
        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)

        # convert bytes to unsigned short array
        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #* Connected to 23.90.158.114 39800
                #* Connected to 23.90.158.10 39698
                #
                if self.MenaServer==True:
                    if port==39698:
                        address="23.90.158.10"
                    if port==39800:
                        address=="23.90.158.114"

                remote.connect((address, port))


                bind_address = remote.getsockname()
                print("* Connected to {} {}".format(address, port))
            else:
                connection.close()

            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        except Exception as e:
            # return connection refused error
            print(e)
            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            
            self.exchange_loop(connection, remote)

        connection.close()

    
    def exchange_loop(self, client:socket.socket, remote:socket.socket):
        while True:
            # wait until client or remote is available for read
            
            r, w, e = select.select([client, remote], [], [])
            
            if client in r:

                data = client.recv(4096)
                if '0315' in data.hex()[0:4]:
                    if len(data.hex()) >=300:
                        print(data.hex())
                #if b"7827699126" in data:
                #    print(">>>>"+data.hex())
                #    print(">>>>"+str(remote))
                #spam chat 
                
                if '1215' in data.hex()[0:4] and self.spam_chat ==True:
                        
                        b = threading.Thread(target=self.Spam_Chat, args=( data,))
                        b.start()

                #Get ip 4 spam
                if "39698" in str(remote) :
                    self.spam_ip_39698 = remote
                if "39800" in str(remote) :
                    self.spam_ip_39800=remote
                    
                    
          
                    
                #Spam Invite 
                if '0515' in data.hex()[0:4] and len(data.hex()) >=820 and self.inviteB==True :
                        try:
                        
                            for i in range(3):
                                threading.Thread(target=self.Spam_Invite , args=(data )).start()
        
                        except:
                            pass

                #AntiKick
                if '0515' in data.hex()[0:4] and len(data.hex()) >= 141 :    
                    self.data_join=data
                       
                if '0515' in data.hex()[0:4] and len(data.hex()) <50 :  
                    self.data_back=data

                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                self.EncryptedPlayerid = data.hex()[12:22]
                #----Welcom_Msg_send ----

                    
                    
                #fo

                    
  
                    
                #back Spam Last Sqo
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b"/ca" in data:
                    self.spamantikick=True
                    threading.Thread(target=self.SpamAntiKick ).start()
                    
                    
                    
                   
                #Spy Normal Last Squd 
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/spy' in data:       
                    self.op.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))

                    
                    
                    
                    
                #Spam Messag
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/lag' in data:     
                    self.spam_chat=True
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[00FF00][b][c]رسالتك من فضلك :")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[00FF00][b][c]رسالتك من فضلك :"))))
                #Spam Messag Off
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/-lag' in data:
                    self.spam_chat=False
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[FF0000][b][c]تم توقيفه!")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[FF0000][b][c]تم توقيفه!"))))
                #Spam Invite
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/des' in data:
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[00FF00][b]الفريق من فضلك!")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[00FF00][b]الفريق من فضلك!"))))
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[4dd0e1][b]توقف : 60 ثانية")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[4dd0e1][b]توقف : 60 ثانية"))))
                    self.inviteB=True               
                #spam Invite Off
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/-des' in data:
                    self.inviteB=False
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[FF0000][b][c]تم توقيفه!")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[FF0000][b][c]تم توقيفه!"))))
                    
   
                #5 sqoud
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/s5' in data:
                    self.spam_ip_39698.send(b'\x05\x03\x00\x00\x01\xd0\x1f\xb5x11P\x90[\xab\xce\xf5\x1d\xd2N\xd7_\xd0\xa2K\x02K\xd1B\x96F\x11K\xc2.`J\xfd5\xa9o\xbcHq\x0b-\x9c\xfe\xc47\x82\x87\xec\x82\x9e3\xa7\x86\x08\xfd-\xd18\xd4\xd2J\x19\xc0\x0f\xbf\xdc\x9f\x15\xc7\x7f\xf8mc\x8b4\xde\x95\xbd\x88n0u\xe8-?J8\x88\xf9\xb6\x944c\x02,C\xfb\x90\xe2)\xf0\xea\xf8\xa7\x88\xf6\xf7f\xd8\x91\xd9\x9e\xb2\xc3{\'qD\x922\x12\x81\x0b<\x80\xd1\xc5!y\x01T\xed\'\x0fRA\xad\xc16\xf2\xa2(\x16\xe0\xbc\x84\xfc\xafy8k\'U\x9d\xe9f\xaax\x8c\x18M5\xbb\xbf\xaa\x03\xa5\xf0\x87F\xf8\xdb\x0es\xb2\xc9\x1e\xc4Q]a\xf6\x89\xa0\xca\xd3\n|\xbdl2QQ\xe8y\xda\xbcC\xd5\x06\xb3$\n\xbeA\xbc\rkD\x16\xc1\x8fh\xefJ\xf2\xd0L8\x1b\xe6\xbfXok%r|\x0c\x85\xc0:W\x917\xe4\xa6\xc6\x02\xefm\x83=\xab\xda\xb3\xeb\xa3\xa5&nZG1\xfb\xfb\x17 \xb6\x0f\x12L\xd8\xfdO\xa2l\xc7\xa9\xfbn\n!\x8d\x88\t\xf5{ M"\xfa\x97R\n\xeb\x99\x00|{q\xc7\t\xe5>\xcch\x8c\x99c\xe0xi\t\x15/\xa9?\x06\xdc\x93\x08Th\xda\xe3N\x16\t\xf3?}\xee"\x8f\xb0X\xc6\xef\xd6\x84kP\xacT\xdb\n\xeb\xb8\xf5\xbc/gQ\xf9\xe2\x88m\xba\xb4\x1c\xba\xf5\xa1\xd8\xcd\x88\xe6\xc1:**V\xb6\x13\xa2\xd3!y\xdc?x\x14\x93\xa5\x02s"\xac\x0c\xb1\xa2\xd3\xc7\x9dI\xfb\x12\xed&#\x0e\x15a\xdfC\xd3\x15\xa2{\xe1{]\xeb\xdb\xa7W\x803\x05%+TC\xf3\xd7|\xd3\x19\xdd\xe9\xc4\x9ar\xc66\xd9=\x02\xbd\xd9Yqh\xf3x\xaanA\xd0\xfdTZ\xbf\x8b\xc0\x88?=\xac\x11\xea\'\x16f\x83\xc7\x11\x1a\x0f2\x9b\xf6\xb6\xa5')
                    
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[00FF00][b]تحويل سكواد 5 تم!")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[00FF00][b][c]تحويل سكواد 5 تم!"))))
                    
                #4 sqoud
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/s4' in data:
                    self.op.send(bytes.fromhex("05150000002000b54843b3c467145c9b8ddcfa4cb489167bd09880be3611b67fec8f0ca66023"))
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[00FF00][b]تحويل سكواد 4 تم!")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[00FF00][b]تحويل سكواد 4 تم!"))))
                #2 sqoud
                if '1200' in data.hex()[0:4] and self.command==True:
                   if b'/s2' in data:
                    self.spam_ip_39698.send(bytes.fromhex("05150000002098a0bdfd5abbd47ea20d1652a8fa374c78f2fe11f3bf6f5a15ac2dff2ecfd436"))
                    client.send(bytes.fromhex(self.MakeMsg4NormalChat(data.hex() ,"[00FF00][b][c]تحويل سكواد 2 تم!")))
                    client.send(bytes.fromhex(str(self.MakeMsg4Clan(data.hex() ,"[00FF00][b]تحويل سكواد 2 تم!"))))
                #----Player Info by ID----    
                if '1200' in data.hex()[0:4] and '33736279' in data.hex() :
                    self.newdataS2=data.hex()
                    self.BackSpam_ip = client
                    self.Target_id= (bytes.fromhex(re.findall(r'33736279(.*?)28' , data.hex()[50:])[0])).decode("utf-8")
                    
                    Thread(target=self.Send_full_information).start()
  
                #----Spy Packet----
                if  '0500' in data.hex()[0:4]  : 
                    if len(data.hex())<=60:
            
                        pass
                    if len(data.hex())>=61:
                        self.packet_back = data
                        self.client_ip = client
                        
                    
                if client.send(data) <= 0:
                    break
                

    
    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])


    def verify_credentials(self, connection):
        
        version = ord(connection.recv(1)) # should be 1


        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')
        
        password_len = ord(connection.recv(1))
        
        password = connection.recv(password_len).decode('utf-8')

        if username  and password :
            # success, status = 0
            response = bytes([version, 0])
            connection.sendall(response)
            return True

        # failure, status != 0
        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False


    def get_available_methods(self, nmethods, connection):
        try:
            methods = []
            for i in range(nmethods):
                methods.append(ord(connection.recv(1)))
            return methods
        except:
            pass

    def run(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()

        print("* Socks5 proxy server is running on {}:{}".format(host, port))

        while True:
            conn, addr = s.accept()
            
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
    def udp_server(self):
    
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ('127.0.0.1', 1234)  
        sock.bind(server_address)
        # Listen for incoming datagrams
        print(f'Server listening on {server_address}')

        while True:
            
            data ,addreOP = sock.recvfrom(1024)
            print(data)
        #----<<<Command>>>---- 
            # ----5mode----
            if b"/5s" in data:  #OP1
                self.Sqd_Fox=True
                Thread(target=self.SQDFOX).start()
            #----spam chat----
            if b"/spamchat" in data:   #OP2
                print("hhh")
            if b"/-spamchat" in data:
                print("TY")
                
            #----spam antikick----
            if b"/antikick" in data:   #OP3
                self.spamantikick=True
                Thread(target=self.SpamAntiKick).start()
            if b"/-antikick" in data:
                self.spamantikick=False
            #----Spy----
            if b"/spy" in data:   #OP4
                try:
                    self.Visible_Fox=True
                    Thread(target=self.SPYFOX).start()
                except Exception as e:
                    print("[+]Exception on :"+str(e))
            #----Back last Group----
            if b"/BacklastGroup" in data:  #OP5
                self.spam_ip_39698.send(self.data_join)
            #----Spam Invit----
            if b"/des" in data:   #OP6
                self.inviteB=True
            if b"/-des" in data:
                self.inviteB=False
            #----Bot Comand----
            if b"/command" in data:   #OP7
                print("TY")
             
            if b"/-command" in data:
                print("TY")
            #----Server Change----
            if b"/Mena" in data:  #OP8
                print("TY")
            if b"/-Mena" in data:
                print("TY")
            #----LVL ++----
            if b"/lvl" in data:  #OP9
                self.Visible_Fox=True
                Thread(target=self.SPYFOX).start()
            if b"/-lvl" in data:
                print("TY")
            #----Like ++----
            if b"/Like" in data:   #O10
                self.Profile_Fox=True
                Thread(target=self.PFPFOX).start()
            if b"/-Like" in data:
                print("TY")
        #----<<<Options>>>----
            if b"OP1" in data:
                sock.sendto("ON".encode(),addreOP)
            if b"OP2" in data:
                sock.sendto("OFF".encode(),addreOP)
            if b"OP3" in data:
                sock.sendto("ON".encode(),addreOP)
            if b"OP4" in data:
                sock.sendto("ON".encode(),addreOP)
            if b"OP5" in data:
                sock.sendto("ON".encode(),addreOP)
            if b"OP6" in data:
                sock.sendto("OFF".encode(),addreOP)
            if b"OP7" in data:
                sock.sendto("OFF".encode(),addreOP)
            if b"OP8" in data:
                sock.sendto("OFF".encode(),addreOP)
            if b"OP9" in data:
                sock.sendto("ON".encode(),addreOP)
            if b"OP10" in data:
                sock.sendto("ON".encode(),addreOP)

            
            

        
    def MakeMsg4NormalChat(self , packet ,replay  ):
        
        replay  = replay.encode('utf-8')
        replay = replay.hex()
        

        hedar = packet[0:8]
        packetLength = packet[8:10] #
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]#
        pyloadbody2= packet[34:60]
        
        pyloadlength = packet[60:62]#
        
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+62):]
        
        
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) ==1:
            NewTextLength = "0"+str(NewTextLength)
            
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]

        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        
        return str(finallyPacket)
        #120000004108aee0ab841d101220022a3508aee0ab841d10e2aabee50318012204626f747328dfd7e3a3064a0f0a09746573745f626f745f20013802520261726a0410011802
    def MakeMsg4Clan(self ,  packet , replay  ):
        replay  = replay.encode('utf-8')
        replay = replay.hex()
        hedar = packet[0:8]
        packetLength = packet[8:10] #
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]#
        pyloadbody2= packet[34:64]
        pyloadlength = packet[64:66]#
        
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+66):]
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) ==1:
            NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        return finallyPacket
    def GetIdStatu(self ,Id):
        r= requests.get('https://ff.garena.com/api/antihack/check_banned?lang=en&uid={}'.format(Id)) 
        a = "0"
        if  a in r.text :
            return("الحساب مش مبند ")
        else: 
            return("تم تعليقه !!")
    def GetNameById(self, Id )  :
        
        url = "https://shop2game.com/api/auth/player_id_login"
        headers = {
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    
        'Origin': 'https://shop2game.com',
        'Referer': 'https://shop2game.com/app',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
        'accept': 'application/json',
        'content-type': 'application/json',
        'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'x-datadome-clientid': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
        }
        payload = {
            "app_id": 100067,
            "login_id": f"{Id}",
            "app_server_id": 0,
        }
        response = requests.post(url, headers=headers, json=payload)
        try:
            if response.status_code == 200:
                return response.json()['nickname']
            else:
                return(f"ERROR")
        except:
            return("عذرا , لم يتم إيجاد حسابك !! ")
    def GetIdRegion(Id):    
        
        url = "https://shop2game.com/api/auth/player_id_login"
        headers = {
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    
        'Origin': 'https://shop2game.com',
        'Referer': 'https://shop2game.com/app',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
        'accept': 'application/json',
        'content-type': 'application/json',
        'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'x-datadome-clientid': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
        }
        payload = {
            "app_id": 100067,
            "login_id": f"{Id}",
            "app_server_id": 0,
        }
        response = requests.post(url, headers=headers, json=payload)
        try:
            if response.status_code == 200:
                return response.json()['region']
            else:
                return(f"ERROR")
        except:
            return("عذرا , لم يتم إيجاد حسابك !!")
    def Spam_Invite(self , data):
        while self.inviteB==True:
            try:
                self.spam_ip_39698.send(data)
                sleep(0.08)
            except:
                pass
    def Spam_Chat(self , data):
        while self.spam_chat==True:
            try:
                self.spam_ip_39800.send(data)
                sleep(0.08)
            except:
                pass
    def Sqoud5mode(self ) :

        self.spam_ip_39698.send(b'\x05\x03\x00\x00\x01\xd0\x1f\xb5x11P\x90[\xab\xce\xf5\x1d\xd2N\xd7_\xd0\xa2K\x02K\xd1B\x96F\x11K\xc2.`J\xfd5\xa9o\xbcHq\x0b-\x9c\xfe\xc47\x82\x87\xec\x82\x9e3\xa7\x86\x08\xfd-\xd18\xd4\xd2J\x19\xc0\x0f\xbf\xdc\x9f\x15\xc7\x7f\xf8mc\x8b4\xde\x95\xbd\x88n0u\xe8-?J8\x88\xf9\xb6\x944c\x02,C\xfb\x90\xe2)\xf0\xea\xf8\xa7\x88\xf6\xf7f\xd8\x91\xd9\x9e\xb2\xc3{\'qD\x922\x12\x81\x0b<\x80\xd1\xc5!y\x01T\xed\'\x0fRA\xad\xc16\xf2\xa2(\x16\xe0\xbc\x84\xfc\xafy8k\'U\x9d\xe9f\xaax\x8c\x18M5\xbb\xbf\xaa\x03\xa5\xf0\x87F\xf8\xdb\x0es\xb2\xc9\x1e\xc4Q]a\xf6\x89\xa0\xca\xd3\n|\xbdl2QQ\xe8y\xda\xbcC\xd5\x06\xb3$\n\xbeA\xbc\rkD\x16\xc1\x8fh\xefJ\xf2\xd0L8\x1b\xe6\xbfXok%r|\x0c\x85\xc0:W\x917\xe4\xa6\xc6\x02\xefm\x83=\xab\xda\xb3\xeb\xa3\xa5&nZG1\xfb\xfb\x17 \xb6\x0f\x12L\xd8\xfdO\xa2l\xc7\xa9\xfbn\n!\x8d\x88\t\xf5{ M"\xfa\x97R\n\xeb\x99\x00|{q\xc7\t\xe5>\xcch\x8c\x99c\xe0xi\t\x15/\xa9?\x06\xdc\x93\x08Th\xda\xe3N\x16\t\xf3?}\xee"\x8f\xb0X\xc6\xef\xd6\x84kP\xacT\xdb\n\xeb\xb8\xf5\xbc/gQ\xf9\xe2\x88m\xba\xb4\x1c\xba\xf5\xa1\xd8\xcd\x88\xe6\xc1:**V\xb6\x13\xa2\xd3!y\xdc?x\x14\x93\xa5\x02s"\xac\x0c\xb1\xa2\xd3\xc7\x9dI\xfb\x12\xed&#\x0e\x15a\xdfC\xd3\x15\xa2{\xe1{]\xeb\xdb\xa7W\x803\x05%+TC\xf3\xd7|\xd3\x19\xdd\xe9\xc4\x9ar\xc66\xd9=\x02\xbd\xd9Yqh\xf3x\xaanA\xd0\xfdTZ\xbf\x8b\xc0\x88?=\xac\x11\xea\'\x16f\x83\xc7\x11\x1a\x0f2\x9b\xf6\xb6\xa5')
    def SpamAntiKick( self ):
        while self.spamantikick==True:
            try:
                self.spam_ip_39698.send(self.data_join)
                sleep(1.2)
                self.spam_ip_39698.send(self.data_back)
            except Exception as e:
                pass     
                
    def SPYFOX(self):
        while self.Visible_Fox==True:
            try:
                self.spam_ip_39698.send(b'\x05\x03\x00\x00\x01\xd0\x1f\xb5x11P\x90[\xab\xce\xf5\x1d\xd2N\xd7_\xd0\xa2K\x02K\xd1B\x96F\x11K\xc2.`J\xfd5\xa9o\xbcHq\x0b-\x9c\xfe\xc47\x82\x87\xec\x82\x9e3\xa7\x86\x08\xfd-\xd18\xd4\xd2J\x19\xc0\x0f\xbf\xdc\x9f\x15\xc7\x7f\xf8mc\x8b4\xde\x95\xbd\x88n0u\xe8-?J8\x88\xf9\xb6\x944c\x02,C\xfb\x90\xe2)\xf0\xea\xf8\xa7\x88\xf6\xf7f\xd8\x91\xd9\x9e\xb2\xc3{\'qD\x922\x12\x81\x0b<\x80\xd1\xc5!y\x01T\xed\'\x0fRA\xad\xc16\xf2\xa2(\x16\xe0\xbc\x84\xfc\xafy8k\'U\x9d\xe9f\xaax\x8c\x18M5\xbb\xbf\xaa\x03\xa5\xf0\x87F\xf8\xdb\x0es\xb2\xc9\x1e\xc4Q]a\xf6\x89\xa0\xca\xd3\n|\xbdl2QQ\xe8y\xda\xbcC\xd5\x06\xb3$\n\xbeA\xbc\rkD\x16\xc1\x8fh\xefJ\xf2\xd0L8\x1b\xe6\xbfXok%r|\x0c\x85\xc0:W\x917\xe4\xa6\xc6\x02\xefm\x83=\xab\xda\xb3\xeb\xa3\xa5&nZG1\xfb\xfb\x17 \xb6\x0f\x12L\xd8\xfdO\xa2l\xc7\xa9\xfbn\n!\x8d\x88\t\xf5{ M"\xfa\x97R\n\xeb\x99\x00|{q\xc7\t\xe5>\xcch\x8c\x99c\xe0xi\t\x15/\xa9?\x06\xdc\x93\x08Th\xda\xe3N\x16\t\xf3?}\xee"\x8f\xb0X\xc6\xef\xd6\x84kP\xacT\xdb\n\xeb\xb8\xf5\xbc/gQ\xf9\xe2\x88m\xba\xb4\x1c\xba\xf5\xa1\xd8\xcd\x88\xe6\xc1:**V\xb6\x13\xa2\xd3!y\xdc?x\x14\x93\xa5\x02s"\xac\x0c\xb1\xa2\xd3\xc7\x9dI\xfb\x12\xed&#\x0e\x15a\xdfC\xd3\x15\xa2{\xe1{]\xeb\xdb\xa7W\x803\x05%+TC\xf3\xd7|\xd3\x19\xdd\xe9\xc4\x9ar\xc66\xd9=\x02\xbd\xd9Yqh\xf3x\xaanA\xd0\xfdTZ\xbf\x8b\xc0\x88?=\xac\x11\xea\'\x16f\x83\xc7\x11\x1a\x0f2\x9b\xf6\xb6\xa5')

            except Exception as e:
                print("[+]Exception on :"+str(e))
                
    def PFPFOX(self):
        while self.Profile_Fox==True:
            try:
                self.spam_ip_39698.send(bytes.fromhex("080000001608edaae28710100820022a0a08bfda5b10fe7d18c801"))
                self.spam_ip_39698.send(bytes.fromhex("080000001608edaae28710100820022a0a08e7be0110b24f18c801"))

            except Exception as e:
                print("[+]Exception on :"+str(e))
                
                
    def SQDFOX(self):
        while self.Sqd_Fox==True:
            
            packet_5 = f"05000001ff08{self.EncryptedPlayerid}1005203a2af20308{self.EncryptedPlayerid}12024d451801200432f70208{self.EncryptedPlayerid}1209424c52585f4d6f642b1a024d4520d78aa5b40628023085cbd1303832421880c38566fa96e660c19de061d998a36180a89763aab9ce64480150c90158e80792010801090a12191a1e209801c901c00101e801018802039202029603aa0208080110e43218807daa0207080f10e4322001aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022812041a0201041a0508501201631a060851120265661a0f0848120b0104050607f1a802f4a8022200ea0204100118018a03009203009803b7919db30ba20319c2b27854e19687e197a95fe191ade192aae197a95945e19687e20301523a011a403e50056801721e313732303237323231313638373535353930315f736f3278687a61366e347801820103303b30880180e0aecdacceba8e19a20100b00114ea010449444332fa011e313732303237323231313638373535383330335f71356f79736b3934716d"
         
            self.spam_ip_39698.send(bytes.fromhex(packet_5))
                


    def SpamLVL(self):
        while self.LVL==True:
            try:
                self.spam_ip_39698.send(bytes.fromhex("0315000001b0e9c8fe1d069792bb3070e576e6cc111e2220b28429bf29149f6db7be1cdd54b3ed3ed89cee324e47abc98de81d093b0a8f4ffcc5ed73b97608a86179d2e30f1bd2f573e82317dee341dc4de72598c2c13ac2dbb5f0e9e3e67d5679c49b0b2191224a937c5899a961f9c0291ce707dfc0808957e45425abab8f4724bd571fa68d9b69e1d330756a087adfd80d7cbf9a21f4d095fdaeb59477dd82579da98ea29c7df48de189bd92373e055851b1d2afe37299c825a195bfc60ea3411dd15f5b8447a037e08c69a533d42a003bc042d2e7fe6e3b3ac6b67fa6eb3299835053e73b18516889fe1a80d8b8c6d1052353247603a4fe63fb0796ebc30c36af0cb452e5ee5b4082750b79fd67e83f71ec9917f9e6a0a283ab3c1ca63fa02dd7b1ebabde7d5286f51076f068ff3957093e030d25ac954dc4a36b9218ca348358c26aeb7a98650ee8c421de6cc511c4ac0d375dfeff68eca0e0acfda8096d8b384ac8ad06b5c0a359c9bb7ba3d225e0c45268f3c494a1b46f5d5abdf6514c41c28c1828c3d308c286933adfe1bd36e38bc6bace21433f062f6a84d32a8da9cef3f294a38d3bcc6b059849d440cc4646691aab2edf"))
                sleep(7)
                self.spam_ip_39698.send(b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8')
            except Exception as e:
                print("[+]Exception on :"+str(e))
    def Welcom_Msg_send(self):
        
        for data in self.__list_:
            sleep(0.8)
            self.spam_ip_39800.send(data)  
    def Send_full_information(self):
        try:
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4NormalChat(self.newdataS2,f"[00FF00][b][c]لحضة  !!")))
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4Clan(self.newdataS2,f"[00FF00][b][c]لحضة  !!")))
            
            
        
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4NormalChat(self.newdataS2,f"[4dd0e1][b][c]جاري تسجيل دخول الحساب.. ")))
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4Clan(self.newdataS2,f"[4dd0e1][b][c]جاري تسجيل دخول الحساب.. ")))                           
            
            
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4NormalChat(self.newdataS2,f"[ff5722][b][c]{self.GetIdStatu(self.Target_id)}")))
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4Clan(self.newdataS2,f"[ff5722][b][c]{self.GetIdStatu(self.Target_id)}")))                           
            
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4NormalChat(self.newdataS2,f"[00FF00][b][c]-----------------------------------")))
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4Clan(self.newdataS2,f"[00FF00][b][c]-----------------------------------")))    
            
            
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4NormalChat(self.newdataS2,f"[FF0000][b][c] FoxyBot (Beta)")))
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4Clan(self.newdataS2,f"[FF0000][b][c] FoxyBot (Beta)")))    
            
            
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4NormalChat(self.newdataS2,f"[00FF00][b][c]@the_foxy999")))
            self.BackSpam_ip.send(bytes.fromhex(self.MakeMsg4Clan(self.newdataS2,f"[00FF00][b][c]@the_foxy999")))  
        except:
            pass
    

def start_bot():
    proxy = Proxy()
    proxy.run("127.0.0.1", 1999)
start_bot()