
'''
   Copyrights owned by Team VoteChain.
   Any contributions to the main source code can be made only after the approval of the Chief Developer.

   Features to be included in the future upgrades:
      -->> Concurrency Control
      -->> Database Connectivity
      -->> Verification of only the Verifiable Blocks
      -->> Proper Code Termination ; Allow any node to withdraw from the network
      -->> Reduce the number of threads from 3N-1
      -->> DH-RSA

      Last Updated: March 07 2019, 2227hrs
                                                                                                            '''

''' #############################################    PACKAGES    ###########################################################################'''


import pickle                                            #  To Pickle and Unpickle Data Before Transmission and After Reception
import json                                              #  To Store the Chain of Blocks
import socket                                            #  Basic Unit of Communication
import datetime                                          #  To Determine the Time of Voting
import time
import hashlib                                           #  To Generate the Hash Codes
import ast
import random                                            #  To select a Random Client During Chain Tampering
import threading                                         #  To Create Multiple Clients and Sending & Receiving Threads


'''###############################################    GLOBAL VARIABLES    ####################################################################'''


d={1:0,2:0,3:0,4:0,5:0}                                  #  Vote Count
noc=1                                                    #  Number of Clients
initiate='null'                                          #  To Indicate that all the Servers have been Setup

msg_S_S='No_Msg'
msg_S_C='No_Msg'
msg_R_S='No_Msg'
msg_R_C='No_Msg'

cp=12345                                                                            #  Client Port Number
sp=12345                                                                            #  Server Port Number
#server_ip=[socket.gethostbyname(''' Fill in the Servers' IPs ''')]                  #  Servers' IP List
mul_c=[]                                                                            #  List of Client Objects

msg_sts_S=-1                                             #  // -1 - No Msg // 0 - Broadcast // Other nos - Client ID // Broadcast or Point to Point from Server 
msg_sts_C=-1                                             #  // -1 - No Msg // Other nos - Client ID for C2S



'''################################################    BLOCK CLASS & FUNCTION    ################################################################'''


class Block:
   def __init__(self, indx, timestamp, vc1, vc2, vc3, vc4, vc5, previous_hash):
    self.indx = indx
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


def next_block(indx, last_block_hash,vc1,vc2,vc3,vc4,vc5,timestamp):
   this_indx = indx+1
   this_timestamp = timestamp
   this_vc1 = vc1
   this_vc2 = vc2
   this_vc3 = vc3
   this_vc4 = vc4
   this_vc5 = vc5
   this_hash = last_block_hash
   return Block(this_indx, this_timestamp, this_vc1, this_vc2, this_vc3, this_vc4, this_vc5, this_hash)



'''###############################################    CLIENT THREAD CLASS    ##########################################################################'''


class ClientThread (threading.Thread):
   def __init__(self, threadID, name):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      
   def run(self):
      print("Starting " + self.name)
      client(self.threadID)      
      print("Exiting " + self.name)


'''###############################################    SEND COMMN THREAD CLASS    ##########################################################################'''


class SendThread (threading.Thread):
   def __init__(self, threadID, name, soc_obj, cc):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      self.soc_obj=soc_obj
      self.cc=cc
      
   def run(self):
      send_msg(self.threadID,self.soc_obj,self.cc)


'''###############################################    RECEIVE COMMN THREAD CLASS    ##########################################################################'''


class ReceiveThread (threading.Thread):
   def __init__(self, threadID, name, soc_obj, cc):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      self.soc_obj=soc_obj
      self.cc=cc
      
   def run(self):
      recv_msg(self.threadID,self.soc_obj,self.cc)

'''################################################    MESSAGES    #############################################################################'''


def send_msg(ID,soc_obj,cc):
   global msg_sts_S
   global msg_sts_C
   global msg_S_S
#   global msg_S_C
#   global msg_R_S
#   global msg_R_C
   if ID==0:
      while True:
         while msg_sts_S==-1:
            pass
         
         if msg_sts_S==0:
            for i in range(cc):
               soc_obj[i].send(msg_S_S)
            msg_sts_S=-1
         else:
            soc_obj[msg_sts_S-1].send(pickle.dumps('Error'))
         
   else:
      while True:
         while msg_sts_C!=ID:
            pass
         time.sleep(3)
         ping=pickle.dumps(open('VoteCount.json','r').read())
         soc_obj[0].send(ping)
         msg_sts_C=-1

def recv_msg(ID,soc_obj,cc):
   global msg_sts_S
   global msg_sts_C
#   global msg_S_S
#   global msg_S_C
   global msg_R_S
   global msg_R_C

   if ID==0:
      while True:
         while msg_sts_S!=-1:
            msg_R_S=pickle.loads(soc_obj[msg_sts_S-1].recv(102400))              ###   102400 IS NOT FIXED  ###   LOOK INTO IT
            msg_sts_S=-1
   else:
      while True:
         ping=pickle.loads(soc_obj[0].recv(1024))
         if ping=='Error':
            msg_sts_C=ID
         else:
            msg_R_C=ping

      


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

   

'''#################################################    CHAIN CHECK FUNCTION    ##########################################################################'''


def chain_check(block_in_chain,fname,soc_obj,cc,tid=0):
#    global msg_sts_C
#    global msg_S_S
#    global msg_S_C
#    global msg_R_C

    global msg_R_S

    ''' Open JSON File & Separate the Dictionaries and Store it in a List '''
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
    ret_l.append(block_in_chain.__dict__)

    '''###################################################################'''
    
    ''' Check the Chain for Possible Tampering and Take Necessary Action '''

    for i in range(len(ret_l)-1):
       block_to_check = Block(ret_l[i]['indx'], ret_l[i]['timestamp'], ret_l[i]['vc1'], ret_l[i]['vc2'], ret_l[i]['vc3'], ret_l[i]['vc4'], ret_l[i]['vc5'], ret_l[i]['previous_hash'])
       next_block_to_check = Block(ret_l[i+1]['indx'], ret_l[i+1]['timestamp'], ret_l[i+1]['vc1'], ret_l[i+1]['vc2'], ret_l[i+1]['vc3'], ret_l[i+1]['vc4'], ret_l[i+1]['vc5'], ret_l[i+1]['previous_hash'])
       if block_to_check.hash==next_block_to_check.previous_hash:
           pass
       else:
         print('\nChain Tampered')
         global msg_sts_S
         msg_sts_S=random.randint(1,cc)
         while msg_R_S=='No_Msg':
             pass
         cvcs=msg_R_S
         msg_R_S='No_Msg'
         cvc_l=[]
         while True:
           try:
             j_cc,n_cc=dec.raw_decode(cvcs)
             cvc_l.append(j_cc)
           except ValueError:
             break
           cvcs=cvcs[n_cc:]

         f=open(fname,'w')
         for item in cvc_l:
           json.dump(item,f)
         f.close()
         break
    else:
       f=open(fname,'a')
       json.dump(block_in_chain.__dict__,f)
       f.close()


'''#########################################################    CLIENT MODULE    ###########################################################################'''


def client(tid):

#   global msg_sts_S
#   global msg_sts_C
#   global msg_S_S
#   global msg_S_C
#   global msg_R_S
#   time.sleep(5)

   global msg_R_C
   s = [socket.socket(socket.AF_INET, socket.SOCK_STREAM)]
   host = '192.168.137.145' #server_ip[tid-1]
   port = cp
   s[0].connect((host, port))

   send_client=SendThread(tid, "Client_Send "+str(tid), s, 1)
   recv_client=ReceiveThread(tid, "Client_Recv "+str(tid), s, 1)

   send_client.start()
   recv_client.start()

   var='null'   
   
   while msg_R_C!='end':
     while msg_R_C=='No_Msg':
        pass
     var=msg_R_C
     msg_R_C='No_Msg'
   
     prev_blk=getlastblock('VoteCount.json')
     block_to_add = next_block(prev_blk['indx'], prev_blk['hash'], var.vc1, var.vc2, var.vc3, var.vc4, var.vc5,var.timestamp)
     block_in_chain = block_to_add

     if block_in_chain.hash==var.hash:
         global d
         d={1:var.vc1,2:var.vc2,3:var.vc3,4:var.vc4,5:var.vc5}
     else:
         print('\nBlock is Tampered')
         print('\nBlock not Added')

     chain_check(block_in_chain,'VoteCount.json',s,1,tid)

   threading.Thread.join(send_client)
   threading.Thread.join(recv_client)

   s.close()


'''###########################################################    SERVER MODULE    #############################################'''


def server():
#    global msg_sts_C
#    global msg_S_C
#    global msg_R_S
#    global msg_R_C

    global msg_S_S
    global msg_sts_S
    global mul_c
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '192.168.137.1' #socket.gethostbyname('HP')
    port = sp
    s.bind((host, port))
    s.listen(5)

    initiate=input("Press 'i' to initiate the client requests... (Only if all Servers are set up)")
    clients=[]
    
    for i in range(noc):
       clients.append(ClientThread(i+1,"Client "+str(i+1)))
       clients[i].daemon=False

    for i in range(noc):
       clients[i].start()
       
    for i in range(noc):
      c, addr = s.accept()
      mul_c.append(c)

    send_serv=SendThread(0, "Serv_Send "+str(0), mul_c, noc)
    recv_serv=ReceiveThread(0, "Serv_Recv "+str(0), mul_c, noc)
    
    send_serv.start()
    recv_serv.start()

    ping='null'

    vid=0
    tag=vid
    ts='0'
    
    while tag!=999:
      while tag!=999:
            vid=int(input('Enter Voter ID '))
            tag=vid
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
                            item['Voter Status']='V'
                            d[n]+=1
                            ts=str(datetime.datetime.now())

                            prev_blk=getlastblock('VoteCount.json')
                            block_to_add = next_block(prev_blk['indx'],prev_blk['hash'], d[1], d[2], d[3], d[4], d[5], ts)

                            block_in_chain = block_to_add
                            msg_S_S=pickle.dumps(block_in_chain)
                            msg_sts_S=0
                            print(msg_sts_S)
                            chain_check(block_in_chain,'VoteCount.json',mul_c,noc)
                            break
                else:
                    pass
            else:
                print('Invalid')
                continue
            

    ping=pickle.dumps('end')
    msg_S=ping
    msg_sts_S=0

    for i in range(noc):
       threading.Thread.join(clients[i])

    threading.Thread.join(send_serv)
    threading.Thread.join(recv_serv)

    s.close()

    
'''###########################################    MAIN MODULE    ######################################'''



block_in_chain = Block(1, 'NULL', 0, 0, 0, 0, 0, '0')
f=open('VoteCount.json','w')
json.dump(block_in_chain.__dict__,f)
f.close()

print("Server")
vd=[]
for i in range(10):
  vd.append({'Voter ID':i+1,'Voter Status':'NV'})  
server()
print('End')

