
'''
                        * Copyrights owned by Team VoteChain *

            * Any contributions to the main source code can be made only after
                        the approval of the Chief Developer Rishi Tharun *

            <<<   This is a new architecture that is under development  >>>
   
   Architecture Details:
         => Node has 5 threads: Main, Send, Receive, BlockAdd, ChainCheck
         => A New Transport Layer Packet Structure is used
         => Single transactions are sent
         => 0.5 seconds delay is imposed before adding a block into the chain   (can be increased)
	 => A hybrid encryption protocol is used to secure data

   Works Pending:
	 => Error control mechanisms (Chaincheck, Tamper Detection)
	 => Implementing the encryption protocol for more than 2 nodes

      Last Updated: October 7 2019, 2031hrs
                                                                                          '''

''' #############################################    PACKAGES    ###########################################################################'''

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import base64
import pickle
import blowfish
import json                                              #  To Store the Chain of Blocks
import socket                                            #  Basic Unit of Communication
import time
import hashlib                                           #  To Generate the Hash Codes
import random                                            #  To select a Random Client During Chain Tampering
import threading                                         #  To Create Multiple Clients and Sending & Receiving Threads
import sys

'''###############################################    GLOBAL VARIABLES    ####################################################################'''


d = {1:0,2:0,3:0,4:0,5:0}                                  #  Vote Count

send_buffer = []
send_buffer_err = []

recv_buffer_blk = {}
recv_buffer_err = []

chain_err_cur = [False, None, 0]
chain_err_oth = [False, None, 0]    # [Error = False, IP = None, BlockNumber = 0] # BlockNumber = 0 implies the entire chain

privatekey_A = None
publickeys = {}

masterkeys = {}

flag = False

'''################################################    PACKET FIELDS    ################################################################'''

signature = [0xfa, 0x5f]	# Packet Signature

node_id = 53			# 6 bit value   ;;;   max ---> 64   ;;;   formatting details ---> format(node_id, '#08b')
vote_id = 1			# 10 bit value   ;;;   max ---> 1024   ;;;   formatting details ---> format(vote_id, '#012b')

nodeNvote = 0 # Concat the fields ---> int(format(node_id, '#08b') + format(vote_id, '#012b')[2:],2)   ;;;   format to 4 nibble hex

votes = 0			# 16 bit value   ;;;   one hot   ;;;	formatting details ---> format((1<<(party-1)), '#018b')

timestamp = '0'			# formatting details ---> format(int(time.time()*(10**7)),'#018x')

p_hash = ''
c_hash = ''

checksum = [0,0]



'''################################################    ADDRESSES    ################################################################'''

interface = 'eth0'		# Interface

src_hw = '08-00-27-f8-42-a7' 	# Source MAC Address 08:00:27:f8:42:a7

src_ipv4 = '127.0.0.1'	#socket.gethostbyname(socket.gethostname()) 	# Source IPv4 Address

dst_hw_ip_list = [('127.0.0.1','ec-8e-b5-53-de-e9')] 


'''################################################    UDP STACK METHODS    ################################################################'''


def sendPacket(block, host, hosthw, key = b'', enc_key = b''):

	global src_ipv4

	global flag

	global signature
	global nodeNvote
	global votes
	global timestamp
	global p_hash
	global c_hash

	encoded_packet = b''
	packet_list = []
	UDPlist = []
	IPlist = []

	dst_ipv4 = host
	dst_hw = hosthw

	for num in dst_hw.split('-'):
	   packet_list.append(int(num,16))	# Ethernet Frame - MAC

	for num in src_hw.split('-'):
	   packet_list.append(int(num,16))	# Ethernet Frame - MAC

	packet_list += [8,0]			# Ethernet Frame - Network Layer Protocol

	IPlist = [0x45, 0x00]			# IP Packet - Version, Header Length, Services


	#############	UDP - CUSTOM PACKET STRUCTURE	#########################
	global node_id
	global vote_id

	UDPlist += signature

	#print(type(block))# is tuple)

	if type(block) is tuple:
		votes = block[0]
		timestamp = block[1][2:]
		p_hash = block[2]
		c_hash = block[3]

		if len(block) == 4:
			nodeNvote = int(format(node_id, '#08b') + format(vote_id, '#012b')[2:],2)
		else:
			nodeNvote = int(format(block[4], '#08b') + format(block[5], '#012b')[2:],2)

		UDPlist.append(int('0x' + format(nodeNvote,'#06x')[2:4],16))
		UDPlist.append(int('0x' + format(nodeNvote,'#06x')[4:],16))

		UDPlist.append(int('0x' + format(votes,'#06x')[2:4],16))
		UDPlist.append(int('0x' + format(votes,'#06x')[4:],16))

		for i in range(0,16,2):
			UDPlist.append(int('0x' + timestamp[i:i+2],16))

		for i in range(0,64,2):
			UDPlist.append(int('0x' + p_hash[i:i+2],16))

		for i in range(0,64,2):
			UDPlist.append(int('0x' + c_hash[i:i+2],16))

	else:
		for item in pickle.dumps(block):
			UDPlist.append(item)
#		print(len(UDPlist))

	#############	UDP - CUSTOM PACKET STRUCTURE	#########################


	IPlist.append(int(format(len(UDPlist),'#06x')[:4],16))
	IPlist.append(int('0x' + format(len(UDPlist),'#06x')[-2:],16))

	IP_ID = format(random.randint(0,65535),'#06x')
	IPlist.append(int(IP_ID[:4],16))
	IPlist.append(int('0x' + IP_ID[4:6],16))
	IPlist += [0x40, 0x00, 0x80, 0x11, 0x00, 0x00]

	for num in src_ipv4.split('.'):
	   IPlist.append(int(num))

	for num in dst_ipv4.split('.'):
	   IPlist.append(int(num))

	IP_chk_sum = checkSum(IPlist)

	IPlist[-10:-8] = [IP_chk_sum[0], IP_chk_sum[1]]


	'''
	#############	UDP - STANDARD	##############
	UDPlist.append(int(format(src_port, '#06x')[:4],16))
	UDPlist.append(int('0x' + format(src_port, '#06x')[-2:],16))
	UDPlist.append(int(format(dst_port, '#06x')[:4],16))
	UDPlist.append(int('0x' + format(dst_port, '#06x')[-2:],16))
	UDPlist.append(int(format(len(payload)+8,'#06x')[:4],16))
	UDPlist.append(int('0x' + format(len(payload)+8,'#06x')[-2:],16))
	UDPlist += [0,0]

	for item in payload:
	   UDPlist.append(item)

	UDP_chk_sum = checkSum(UDPpseudo_p + UDPlist)
	UDPlist[-2 - len(payload):-len(payload)] = [UDP_chk_sum[0], UDP_chk_sum[1]]
	#############	UDP - STANDARD	##############
	'''
	

	packet_list += IPlist + UDPlist
	checksum = checkSum(packet_list)
	packet_list.append(checksum[0])
	packet_list.append(checksum[1])
	packet_list += [0,0]

	for item in packet_list[:len(packet_list)-80]:
	   encoded_packet += chr(item).encode('utf-16')[2:3]

	if key == b'':
		for item in packet_list[-80:]:
		   encoded_packet += chr(item).encode('utf-16')[2:3]
	elif flag == False:
		packet_str = b''
		for item in packet_list[-80:]:
			packet_str += chr(item).encode('utf-16')[2:3]

		while packet_str != b'':
			#print(len(packet_str[:8]))
			encoded_packet += key.encrypt_block(packet_str[:8])
			packet_str = packet_str[8:]
		flag = not flag
	else:
		packet_str = b''

		for item in packet_list[-80:]:
			packet_str += chr(item).encode('utf-16')[2:3]

		#print('\n\n',packet_str,'\n',len(packet_str),'\n\n')

		cipher = key.encrypt(packet_str)
		encoded_packet += cipher
		flag = not flag


	encoded_packet += enc_key + chr(not flag).encode('utf-16')[2:3]
	return (encoded_packet, packet_list)


def checkSum(byte_list):
	word_list=[]
	if len(byte_list)%2 != 0:
		byte_list.append(0)
	else:
		pass
	for i in range(0,len(byte_list),2):
		word_list.append(format(byte_list[i],'#04x')+format(byte_list[i+1],'#04x')[-2:])
	chk_sum=0
	for item in word_list:
		chk_sum += int(item,16)
	chk_sum = 65535 - int(('0x'+hex(chk_sum)[-4:]),16) - int(('0x'+hex(chk_sum)[2:-4]),16)
	chk_sum = format(chk_sum,'#06x')
	return (int(chk_sum[:4],16), int('0x' + chk_sum[4:],16))


def hexDump(decoded_packet, dispstr):
	print('\n\n\t       -------------------------------------------\n\t       ',dispstr,'...')
	print('\t       -------------------------------------------\n\n 0x00 |\t', end = '')

	col_count=0
	row_count=0
	for item in decoded_packet:
		print(format(item,'#04x'), end = ' ')
		col_count+=1
		if col_count == 8:
			print(end = '  ')
		elif col_count == 16:
			row_count+=1
			print('\n',format(row_count,'#04x'),'|\t', end = '')
			col_count = 0
		else:
			pass



'''################################################    BLOCK CLASS & FUNCTION    ################################################################'''

class Block:
   def __init__(self, indx, node, timestamp, vc1, vc2, vc3, vc4, vc5, previous_hash):
    self.indx = indx
    self.node = node
    self.timestamp = timestamp
    self.vc1 = vc1
    self.vc2 = vc2
    self.vc3 = vc3
    self.vc4 = vc4
    self.vc5 = vc5
    self.previous_hash = previous_hash
    self.hash = self.hash_block()

   def hash_block(self):
    sha = hashlib.sha256()
    sha.update((str(self.indx) + str(self.timestamp) + str(self.vc1)+ str(self.vc2)+ str(self.vc3)+ str(self.vc4)+ str(self.vc5) + str(self.previous_hash)).encode("utf-8"))
    return sha.hexdigest()


'''###############################################    SEND THREAD CLASS    ############################################################################'''


class SendThread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
      
   def run(self):
      send_msg()


'''###############################################    RECEIVE THREAD CLASS    ##########################################################################'''


class ReceiveThread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
      
   def run(self):
      recv_msg()


'''###############################################    BLOCK ADD THREAD CLASS    ########################################################################'''


class BlockAddThread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
      
   def run(self):
      block_add()


'''###############################################    BLOCK ADD THREAD CLASS    ########################################################################'''


class ChainCheckThread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
      
   def run(self):
      chain_check()

'''###############################################    THREAD METHODS    #######################################################################'''

def send_msg():
   global send_buffer
   global ip_list
   global recv_buffer_blk
   global publickeys
   global masterkeys
   global privatekey_A

   global flag


   try:
      s = socket.socket ( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
   except:
      print ("\nError in Creating Socket. Run the code in a Linux Machine as Root User to avoid this error.")
      sys.exit(0)

   while True:
      try:
         s.bind((interface, 0))
         break
      except:
         print("\nInvalid Interface !")


   input('Press Enter to start...')

### LAYER 1

   privatekey_A = RSA.generate(1024)
   publickey_A = privatekey_A.publickey()

   for host in dst_hw_ip_list:
      enp, pl = sendPacket(publickey_A, host[0],host[1])
      s.send(enp)

### LAYER 2

   masterkey_A = ''.join(chr(random.randint(65, 123)) for i in range(16))
   aes_A = AES.new(masterkey_A)
   
   time.sleep(3)
   for host in dst_hw_ip_list:
      masterkey_enc_A = publickeys[host[0]].encrypt(masterkey_A.encode(),32)[0]
      enp, pl = sendPacket(masterkey_enc_A, host[0],host[1])
      s.send(enp)

### LAYER 3

   while True:

      Bkey_A = ''.join(chr(random.randint(65, 123)) for i in range(16))

      if flag == False:
         Bkey_enc_A = blowfish.Cipher(b'' + Bkey_A.encode())

      else:
         Bkey_enc_A = AES.new(Bkey_A)

      mk_enc_Bkey_A = aes_A.encrypt(Bkey_A)


      if send_buffer == []:
         pass
      else:
         block_to_send = send_buffer[0]

         send_buffer.remove(block_to_send)


         for host in dst_hw_ip_list:
            enp, pl = sendPacket(block_to_send, host[0],host[1], Bkey_enc_A, mk_enc_Bkey_A)
            s.send(enp)

         rb = '0x'
         for item in pl[40:48]:
            rb += format(item,'#04x')[2:]

         recv_buffer_blk[int(rb,16)] = pl

   s.close()


def recv_msg():
   global recv_buffer_blk
   global publickeys
   global masterkeys
   global privatekey_A


   try:
      s = socket.socket ( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
   except:
      print ("\nError in Creating Socket. Run the code in a Linux Machine as Root User to avoid this error.")
      sys.exit(0)

   while True:
      try:
         s.bind((interface, 0))
         break
      except:
         print("\nInvalid Interface !")

   publickey_B = s.recv(1024)

   ip_pk = ''
   for item in publickey_B[26:30]:
      ip_pk += str(item) + '.'
   ip_pk = ip_pk[:-1]

   publickey_B = publickey_B[36:]
   publickey_B = pickle.loads(publickey_B)

   publickeys[ip_pk] = publickey_B

   masterkey_enc_B = s.recv(1024)

   ip_mk = ''
   for item in masterkey_enc_B[26:30]:
      ip_mk += str(item) + '.'
   ip_mk = ip_mk[:-1]

   masterkey_enc_B = masterkey_enc_B[36:]
   masterkey_enc_B = pickle.loads(masterkey_enc_B)

   masterkey_B = privatekey_A.decrypt(masterkey_enc_B).decode()
   aes_B = AES.new(masterkey_B)

   masterkeys[ip_mk] = aes_B


   while True:
      received_packet = s.recv(1024)
      dec_data = b''
      decoded_packet = []

      ##################	ARP CHECK MECH MUST BE INCLUDED		################

      for i in range(len(received_packet)):
         decoded_packet.append(int(received_packet[i]))



      if decoded_packet[23] !=17:
         continue
      else:
         pass

      if decoded_packet[34:36] != [250,95]:
         continue
      else:
         pass

      ip_blk = ''
      for item in decoded_packet[26:30]:
         ip_blk += str(item) + '.'
      ip_blk = ip_blk[:-1]
      

      decrypted_packet = []

      for item in decoded_packet[:36]:
         decrypted_packet.append(item)

      if decoded_packet[-1] == 0:
         #BF
         decoded_packet = decoded_packet[:-1]
         received_packet = received_packet[:-1]

         Bkey_B = masterkeys[ip_blk].decrypt(received_packet[-16:]).decode()
         Bkey_enc_B = blowfish.Cipher(b'' + Bkey_B.encode())

         enc_data = received_packet[36:len(received_packet)-16]
         plaintext = b''
         while enc_data != b'':
            plaintext += Bkey_enc_B.decrypt_block(enc_data[:8])
            enc_data = enc_data[8:]

         for item in plaintext:
            decrypted_packet.append(int(item))

         for item in decoded_packet[-16:]:
            decrypted_packet.append(item)

         hexDump(decoded_packet + [0], 'Hex Dump of Blowfish Encrypted Packet')
         hexDump(decrypted_packet + [0], 'Hex Dump of Blowfish Decrypted Packet')
         print('\n\nPress Enter...')


      else:
         #AES
         decoded_packet = decoded_packet[:-1]
         received_packet = received_packet[:-1]

         Bkey_B = masterkeys[ip_blk].decrypt(received_packet[-16:]).decode()
         Bkey_enc_B = AES.new(Bkey_B)

         enc_data = received_packet[36:len(received_packet)-16]

         plaintext = Bkey_enc_B.decrypt(enc_data)#.decode()

         for item in plaintext:
            decrypted_packet.append(int(item))

         for item in decoded_packet[-16:]:
            decrypted_packet.append(item)

         hexDump(decoded_packet + [1], 'Hex Dump of AES Encrypted Packet')
         hexDump(decrypted_packet + [1], 'Hex Dump of AES Decrypted Packet')
         print('\n\nPress Enter...')


      rb = '0x'
      for item in decrypted_packet[40:48]:
         rb += format(item,'#04x')[2:]
#      print(rb)

      recv_buffer_blk[int(rb,16)] = decrypted_packet

   s.close()


def block_add():
   global recv_buffer_blk
   global src_ipv4

   while True:
      time.sleep(0.5)
      
      if recv_buffer_blk == {}:
         continue
      else:
         ts = min(recv_buffer_blk)
         block_to_add = recv_buffer_blk.pop(ts)

         ipchk = ''
         for item in block_to_add[26:30]:
             ipchk += str(item) + '.'
         ipchk = ipchk[:-1]

         nvi = format(int(format(block_to_add[36],'#04x')+format(block_to_add[37],'#04x')[2:],16),'#018b')[2:]
         ni = int('0b'+nvi[:6],2)
         vi = int('0b'+nvi[6:],2)

         v = int(format(int(format(block_to_add[38],'#04x')+format(block_to_add[39],'#04x')[2:],16),'#018b'),2)

         i = 0
         while v!=0:
           i+=1
           v>>=1

         global d
         if ipchk == src_ipv4:
            pass
         else:
            d[i] += 1

         prev_blk = getlastblock('VoteCountN1.json')
         block_to_add = Block(vi, ni, ts, d[1], d[2], d[3], d[4], d[5], prev_blk['hash'])
         #print(block_to_add.__dict__)

         f=open('VoteCountN1.json','a')
         json.dump(block_to_add.__dict__,f)
         f.close()

         #chain_check()




def chain_check():
	''' Open JSON File & Separate the Dictionaries and Store it in a List '''
	### This portion of the code must be replaced with the Database Accessing ###

	dec = json.JSONDecoder()
	f = open('VoteCountN1.json','r').read()
	print(f)

	block_list = []

	for i in range(1,5):
	   try:
	      f[i*(-267):]
	   except:
	      break

	else:
	   f = f[i*(-267):]


	while True:
	   try:
	      block_dict, n_c = dec.raw_decode(f)
	      block_list.append(block_dict)
	   except:
	      break
	   f = f[n_c:]

#	print(block_list)

	'''###################################################################'''
    
	''' Check the Chain for Possible Tampering and Take Necessary Action '''

	global dst_hw_ip_list
	global send_buffer_err


	for i in range(len(block_list)-1):
		block_to_check = Block(block_list[i]['indx'], block_list[i]['node'], block_list[i]['timestamp'], block_list[i]['vc1'], block_list[i]['vc2'], block_list[i]['vc3'], block_list[i]['vc4'], block_list[i]['vc5'], block_list[i]['previous_hash'])
		next_block_to_check = Block(block_list[i+1]['indx'], block_list[i+1]['node'], block_list[i+1]['timestamp'], block_list[i+1]['vc1'], block_list[i+1]['vc2'], block_list[i+1]['vc3'], block_list[i+1]['vc4'], block_list[i+1]['vc5'], block_list[i+1]['previous_hash'])

		if block_to_check.hash == next_block_to_check.previous_hash:
			print('\n\nno tamp\n\n')
		else:
			print('\n\ntampered\n\n')
			send_buffer_err.append((int(format(0, '#018b'),2), format(2,'#02x') + format(int(time.time()*(10**7)),'#018x')[3:], '0x'+('0'*32), '0x'+('0'*32), block_to_check.node, block_to_check.indx))


'''#################################################    GET LAST BLOCK OF CHAIN    #######################################################################'''

def getlastblock(fname):

   ### This portion of the code must be replaced with the Database Accessing ###
   
   dec=json.JSONDecoder()
   f=open(fname,'r').read()
   ret_l=[]
   while True:
    try:
      j_c,n_c=dec.raw_decode(f)
      ret_l.append(j_c)
    except ValueError:
      break
    f=f[n_c:]

   return ret_l[-1]

'''###########################################################    MAIN MODULE    #############################################'''


def main():


    ping='null'
    vid=0
    ts='0'
    
    while vid!=999:
         input()
         vid=int(input('Enter Voter ID '))

         for item in vd:
             if item['Voter ID'] == vid:
                 if item['Voter Status'] !='NV':
                     print('Voter Already Voted')
                     break
                 else:
                     print('1. Party A')
                     print('2. Party B')
                     print('3. Party C')
                     print('4. Party D')
                     print('5. Party E')
                     n=int(input('Choose your party '))
                     if n not in (1,2,3,4,5):
                         print('Invalid')
                     else:
                         global send_buffer # = []
                         global recv_buffer_blk
                         global vote_id
                         global node_id
                         global d

                         d[n] += 1

                         vote_id += 1

                         item['Voter Status']='V'

                         timestamp=format(int(time.time()*(10**7)),'#018x')[3:]		### CHANGED TO 15 NYBBLES

                         error_nyb = format(0,'#02x')

                         prev_blk=getlastblock('VoteCountN1.json')
                         block_to_add = Block(vote_id, node_id, int(error_nyb + timestamp,16), d[1], d[2], d[3], d[4], d[5], prev_blk['hash'])
                         block_in_chain = block_to_add
                         #print(block_to_add.__dict__)

                         votes = int(format((1<<(n-1)), '#018b'),2)
                         p_hash = prev_blk['hash']
                         c_hash = block_in_chain.hash

#                         print(error_nyb + timestamp)

                         send_buffer.append((votes, error_nyb + timestamp, p_hash, c_hash))

                         break
             else:
                 pass
         else:
             print('Invalid')
             continue

    threading.Thread.join(st)
    threading.Thread.join(rt)
    threading.Thread.join(bt)
    
'''###########################################    MAIN MODULE    ######################################'''

block_in_chain = Block(vote_id, node_id, int(format(int(time.time()*(10**7)),'#018x'),16), 0, 0, 0, 0, 0, '0')
f=open('VoteCountN1.json','w')
json.dump(block_in_chain.__dict__,f)
f.close()

print("Server")
vd=[]
for i in range(10):
  vd.append({'Voter ID':i+1,'Voter Status':'NV'})  


st = SendThread()
rt = ReceiveThread()
bt = BlockAddThread()

st.start()
rt.start()
bt.start()

time.sleep(2)
main()
