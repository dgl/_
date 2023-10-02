from pwn import * 
from google.protobuf.internal.encoder import _VarintEncoder
from google.protobuf.internal.decoder import _DecodeVarint
import server_pb2 as spb
from google.protobuf.internal.decoder import _DecodeError
import sys 
import argparse

def send_message(s, msg):
    """ Send a message, prefixed with its size, to a TPC/IP socket """
    data = msg.SerializeToString()
    mh = spb.MessageHeader()
    mh.msglen = len(data)
    mh.type = msg.type
    s.send(mh.SerializeToString() + data)
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

def recv_message(s):
    """ Receive a message, prefixed with its size and type, from stdin """
    # Receive the size of the message data
    # expect [MessageHeader][Message of type]
    data = b''
    header = spb.MessageHeader()
    while True:
        data+= s.recv(1)
        try:
            header.ParseFromString(data)
            if check_fields(header):
                break
        except _DecodeError as e:
            pass

    # Receive the message data
    data = s.recv(header.msglen)

    # Decode the message and validate all required fields are present
    msg = msg_type(header.type)
    if msg != None:
        try:
            msg.ParseFromString(data)
            if not check_fields(msg):
                return None
            return msg
        except _DecodeError:
            return None
    else:
        return None


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--remote', help="The address:port of the remote server hosting the challenge", required=True)
    args = parser.parse_args()

    if args.remote != None:
        host = args.remote.split(":")[0]
        port = int(args.remote.split(":")[1])
    else:
        exit(0)

    s = remote(host,port )

    ## REGISTER
    rr = spb.RegisterRequest()
    rr.type = spb.MSG_REGISTER_REQUEST
    rr.name = b"TestName"
    rr.password = b"TestPassword"
    send_message(s, rr)

    ## REGISTER RESPONSE
    reg_resp = recv_message(s)
    if reg_resp != None:
        log.info("DEBUG: received {}".format(reg_resp))

    ## LOGIN
    l = spb.LoginRequest()
    l.type = spb.MSG_LOGIN_REQUEST
    l.uid = reg_resp.uid
    l.password = b"TestPassword"
    send_message(s, l)

    ## LOGIN RESPONSE
    login_resp = recv_message(s)
    if login_resp != None:
        log.info("DEBUG: received {}".format(login_resp))

    ## REQUEST MESSAGE
    msg_req = spb.MessageRequest()
    msg_req.type = spb.MSG_MESSAGE_REQUEST
    msg_req.uid = login_resp.uid
    msg_req.role = spb.USER
    msg_req.token.CopyFrom(login_resp.token)

    send_message(s, msg_req)

    msg_resp = recv_message(s)
    if msg_resp != None:
        log.info("DEBUG: received {}".format(msg_resp))

    ## REQUEST FLAG AS USER
    flag_req = spb.FlagRequest()
    flag_req.type = spb.MSG_FLAG_REQUEST
    flag_req.uid = login_resp.uid
    flag_req.role = spb.USER
    flag_req.token.CopyFrom(login_resp.token)

    send_message(s, flag_req)

    flag_resp = recv_message(s)
    if flag_resp != None:
        log.info("DEBUG: received {}".format(flag_resp))

    s.close()

