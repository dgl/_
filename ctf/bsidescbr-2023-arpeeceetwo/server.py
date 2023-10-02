#!/usr/bin/python3

# protoc -I=. --python_out=. ./server.proto
# socat -d TCP-LISTEN:2323,reuseaddr,fork EXEC:"python3 server_stdio_3.py"

import socket
from socket import create_server
from google.protobuf.internal.encoder import _VarintEncoder
from google.protobuf.internal.decoder import _DecodeVarint
import server_pb2 as spb
from google.protobuf.internal.decoder import _DecodeError

import Crypto.Hash.MD5 as MD5
import Crypto.Hash.HMAC as hmac

import logging
import os
import sys

from cybears import flag

#logging.root.setLevel(logging.DEBUG)
#logging.root.setLevel(logging.INFO)
logging.root.setLevel(logging.ERROR)

logger = logging.getLogger("__name__")

h1 = logging.StreamHandler(sys.stderr)
h1.setLevel(logging.DEBUG)
h2 = logging.StreamHandler(sys.stderr)
h2.setLevel(logging.INFO)

logger.addHandler(h1)
logger.addHandler(h2)

# server key for token signatures
KEY = os.urandom(32)

def send_message(msg):
    """ Send a message, prefixed with its size, to stdout """
    data = msg.SerializeToString()
    mh = spb.MessageHeader()
    mh.msglen = len(data)
    mh.type = msg.type
    sys.stdout.buffer.write(mh.SerializeToString() + data)
    sys.stdout.flush()
    logging.info("Sent msg over stdout...")
    return 

def msg_type(msgtype):
    if msgtype == spb.MSG_LOGIN_REQUEST:
        return spb.LoginRequest()
    elif msgtype == spb.MSG_LOGIN_RESPONSE:
        return spb.LoginResponse()
    elif msgtype == spb.MSG_REGISTER_REQUEST:
        return spb.RegisterRequest()
    elif msgtype == spb.MSG_REGISTER_RESPONSE:
        return spb.RegisterResponse()
    elif msgtype == spb.MSG_MESSAGE_REQUEST:
        return spb.MessageRequest()
    elif msgtype == spb.MSG_MESSAGE_RESPONSE:
        return spb.MessageResponse()
    elif msgtype == spb.MSG_FLAG_REQUEST:
        return spb.FlagRequest()
    elif msgtype == spb.MSG_FLAG_RESPONSE:
        return spb.FlagResponse()
    else:
        return None   

def check_fields(msg):
    result = True
    for field in msg.DESCRIPTOR.fields_by_name.keys():
        if msg.DESCRIPTOR.fields_by_name[field].label == msg.DESCRIPTOR.fields_by_name[field].LABEL_REQUIRED:
            result &= msg.HasField(field)
    return result

def recv_message():
    """ Receive a message, prefixed with its size and type, from stdin """
    # Receive the size of the message data
    # expect [MessageHeader][Message of type]
    data = b''
    header = spb.MessageHeader()
    while True:
        data+= sys.stdin.buffer.read(1)
        try: 
            header.ParseFromString(data)
            if check_fields(header):
                break
        except _DecodeError as e: 
            pass
    logging.debug("header {}".format(header))

    # Receive the message data
    data = sys.stdin.buffer.read(header.msglen)
    logging.debug("received [{}]".format(data))

    # Decode the message and validate all required fields are present
    msg = msg_type(header.type)
    if msg != None: 
        try:
            msg.ParseFromString(data)
            if not check_fields(msg):
                return None
            logging.debug("msg {}".format(msg))
            return msg
        except _DecodeError:
            return None
    else:
        return None

def handle_register_request(msg):
    logging.debug("Got register request")
    # validate request
    if msg.HasField("salt"):
        salt = msg.salt
    else:
        salt = b''        

    # parse request
    uid = register_user(USERS, msg.name, msg.password, salt)

    # send response
    resp = spb.RegisterResponse()
    resp.type = spb.MSG_REGISTER_RESPONSE
    resp.uid = uid
    resp.status = spb.SUCCESS
    send_message(resp) 
    logging.info("SUCCESS: User registered with uid: {}".format(uid))

    return None

def build_token(uid, role, salt):
    t = spb.UnsignedToken()
    t.uid = uid
    t.role = role
    t.salt = salt
    return t

def sign_token(token, KEY):
    st = spb.SignedToken()
    st.token.CopyFrom(token)
    try:
        m = MD5.new(token.SerializeToString()).digest()
    except: #Serialize can fail if all fields not present in token
        return None
    st.signature = hmac.new(KEY, m).digest()
    return st 

def verify_token(stoken, KEY): 
    t2 = spb.UnsignedToken()
    t2.CopyFrom(stoken.token)
    try:
        m = MD5.new(t2.SerializeToString()).digest()
    except: #Serialize can fail if all fields not present in stoken
        return None
    check_sig = hmac.new(KEY, m).digest()
    return check_sig == stoken.signature 

def handle_login_request(msg):
    logging.debug("Got Login request")
    # validate request
    if msg.uid > len(USERS) or msg.uid == 0: 
        logging.info("ERROR: invalid uid")
        exit(0)

    requested_user = USERS[msg.uid - 1]

    # parse request
    hash_to_check = hash_password(msg.password, requested_user['salt'])
    
    # send response
    if hash_to_check != requested_user['hashed_password']: 
        resp = spb.LoginResponse()
        resp.type = spb.MSG_LOGIN_RESPONSE
        resp.uid = msg.uid
        resp.status = spb.FAILURE
        logging.info("Login failed, incorrect password")
        logging.debug("{}".format(resp))
        send_message(resp)
        return None
    
    resp = spb.LoginResponse()
    resp.type = spb.MSG_LOGIN_RESPONSE
    resp.uid = msg.uid
    resp.status = spb.SUCCESS
  
    # Generate signed token for user to securely use to request messages
    salt = requested_user['salt'] 
    token = build_token(resp.uid, requested_user['role'], salt)
    stoken = sign_token(token, KEY)
    resp.token.CopyFrom(stoken)
    logging.debug("Sending signed token {}".format(resp))    
    logging.info("SUCCESS: User correctly logged in with uid: {}".format(msg.uid))
    send_message(resp)

    return None

def handle_message_request(msg):
    logging.debug("Got message request")
    # validate request
    # parse request
    # send response
    if not verify_token(msg.token, KEY):
        resp = spb.MessageResponse()
        resp.type = spb.MSG_MESSAGE_RESPONSE
        resp.uid = msg.uid
        resp.status = spb.FAILURE
        resp.msg = "ERROR: Invalid token".encode()
        logging.info("ERROR: Message: invalid token")
        send_message(resp)
        return None
    
    resp = spb.MessageResponse()
    resp.type = spb.MSG_MESSAGE_RESPONSE
    resp.uid = msg.uid
    resp.status = spb.SUCCESS
    resp.msg = "Welcome uid:{}, your role is {}".format(msg.token.token.uid, msg.token.token.role).encode()
    logging.info("SUCCESS: message sent") 
    send_message(resp)

    return None

def handle_flag_request(msg):
    logging.debug("Got flag request")
    
    # validate request
    if not verify_token(msg.token, KEY):
        resp = spb.FlagResponse()
        resp.type = spb.MSG_FLAG_RESPONSE
        resp.uid = msg.uid
        resp.status = spb.FAILURE
        resp.msg = "ERROR: Invalid token".encode()
        logging.info("ERROR: FlagMessage: invalid token")
        send_message(resp)
        return None

    # parse request - user request
    if msg.token.token.role == spb.USER: 
        resp = spb.FlagResponse()
        resp.type = spb.MSG_FLAG_RESPONSE
        resp.uid = msg.token.token.uid
        resp.status = spb.FAILURE
        resp.msg = "Welcome uid:{}. you are not an admin, no flag for you".format(resp.uid).encode()
        logging.info("ERROR: Wrong UID for flag message")
        send_message(resp)
        return None
              
    # parse request - admin request
    if msg.token.token.role == spb.ADMIN:
        resp = spb.FlagResponse()
        resp.type = spb.MSG_FLAG_RESPONSE
        resp.uid = msg.uid
        resp.status = spb.SUCCESS
        resp.msg = "Welcome uid:{}, here is your FLAG: {}".format(resp.uid, flag).encode() 
        send_message(resp)
        return None

def hash_password(password, salt):
    h = MD5.new()
    h.update(password+salt)
    return h.digest()

def register_user(USERS, name, password, salt, role = spb.USER):
    if salt == b'':
        salt = os.urandom(32)
    len_db = len(USERS)
    uid = len_db + 1
    hashed_password = hash_password(password,salt) 
    USERS.append( {"name": name, "hashed_password": hashed_password, "salt": salt, "uid":uid, "role": role} )
    logging.debug("users = {}".format(USERS))
    return uid

if __name__ == "__main__":
    # create user database
    # create admin user
    USERS = []
    register_user(USERS, b"admin", os.urandom(32).hex().encode(), b'', role = spb.ADMIN)  

    while True:
        while True:
           m  = recv_message()
           if m != None:
               if m.type == spb.MSG_REGISTER_REQUEST:
                   handle_register_request(m)
                   continue
               elif m.type == spb.MSG_LOGIN_REQUEST:
                   handle_login_request(m)
                   continue
               elif m.type == spb.MSG_MESSAGE_REQUEST:
                   handle_message_request(m)
                   continue
               elif m.type == spb.MSG_FLAG_REQUEST:
                   handle_flag_request(m)
                   continue
               else:
                   logging.error("Unknown message type, exitting...")
                   exit(0)
