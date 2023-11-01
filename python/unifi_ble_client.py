#
# unifi_ble_client : Client to talk to UniFi devices via BLE
#
# Some UniFi devices listen on BLE for initial device configuration. A mobile
# app is usually required to setup these devices. This module can be used to
# perform some of the configuration steps; specifically, it can be used to
# provide the device with credentials for logging onto a WiFi network, at
# which point the device can be further interacted with via IP on the network.
#
# Currently only tested on:
# - UniFi Protect G3 Instant
#

from enum import Enum

import sys
import os
import re
import struct
import asyncio
import json
import zlib
import logging

import msgpack
import nacl
import nacl.secret
import nacl.public
import nacl.bindings
import bleak

LOG = logging.getLogger(__name__)
(DCRIT, DERROR, DWARN, DINFO, DBG) = (LOG.critical, LOG.error, LOG.warning, LOG.info, LOG.debug)

# These should always be constant as they are declared in `Lcom/ubnt/ble/protocol/BleProtocol;`.
READ_UUID = "d587c47f-ac6e-4388-a31c-e6cd380ba043"
WRITE_UUID = "9280f26c-a56f-43ea-b769-d5d732e1ac67"
# This should also be constant, and is declared in `Lcom/ubnt/ble/auth/DefaultAuth;`.
DEFAULT_KEY = b"\xa7\x81\xf8\xa4\xa6\x27\x37\x3b\x70\x74\x57\x38\xcd\xff\xdd\x1d\xe9\xae\x35\x25\x17\xc3\x74\xca\x9a\xfc\x21\x5c\x39\xc6\x26\x37"

DEVICE_MAP = {
    "g3-instant" : {
        "bt_name_prefix" : "G3 Instant-",
        "service_uuid" : "0c430d0c-00ef-4367-bc6f-ca7c51e6b61f",
    },
}

#
# EXCEPTIONS
#

class Exn(Exception): pass
class CannotFindDeviceExn(Exn): pass
class MultipleDevicesExn(Exn): pass
class CannotAutoDetectModelExn(Exn): pass

#
# CRYPTO
#

def create_nonce(n): return struct.pack(">H", n) + (b"\0" * 22)

def gen_dh_keypair():
    priv_key = nacl.public.PrivateKey.generate()
    return (bytes(priv_key), bytes(priv_key.public_key))
#enddef

def encrypt_ble_packet(data, seqno, key):
    box = nacl.secret.SecretBox(key)
    return box.encrypt(data, nonce=create_nonce(seqno)).ciphertext
#enddef

def decrypt_ble_packet(data, seqno, key):
    box = nacl.secret.SecretBox(key)
    return box.decrypt(data, nonce=create_nonce(seqno))
#enddef

#
# PACKET CREATION / PARSING
#

def pack_ble_packet(data, protocol, seqno, key):
    plaintext_wrapper = struct.pack(">HB", seqno, protocol) + data
    encrypted_wrapper = encrypt_ble_packet(plaintext_wrapper, seqno, key)
    total_len = len(encrypted_wrapper) + 2
    return struct.pack(">H", total_len) + encrypted_wrapper
#enddef

def pack_dh_pubkey(pubkey):
    packer = msgpack.Packer()
    return b"".join((
        packer.pack_array_header(3),
        packer.pack("DHPK"),
        packer.pack(False),
        packer.pack(bytes(pubkey))
    ))
#enddef

def pack_auth_ok_packet():
    return msgpack.dumps(("AUTH", "DH"))
#enddef

def unpack_ble_packet(buf, seqno, key):

    (total_size,) = struct.unpack(">H", buf[:2])
    if len(buf) < total_size:
        raise Exn("Unpacked buffer size is {} but expecting {}.".format(len(buf), total_size))
    elif len(buf) > total_size:
        DWARN("unpack_ble_packet buffer size is {}, but expecting {}. Truncating.".format(len(buf), total_size))
        buf = buf[:total_size]
    #endif
    
    encrypted_wrapper = buf[2:]
    plaintext_wrapper = decrypt_ble_packet(encrypted_wrapper, seqno, key)
    (received_seqno, protocol) = struct.unpack(">HB", plaintext_wrapper[:3])
    return (received_seqno, protocol, plaintext_wrapper[3:])
#enddef

def peek_ble_packet_size(buf):
    (total_size,) = struct.unpack(">H", buf[:2])
    return total_size
#enddef

def unpack_dh_pubkey(pkt_data):
    (header, somebool, pubkey) = msgpack.loads(pkt_data)
    assert header == "DHPK"
    return pubkey
#enddef

def unpack_auth_ok_packet(pkt_data):
    (header1, header2) = msgpack.loads(pkt_data)
    assert header1 == "AUTH" and header2 == "DH"
    return True
#enddef

#
# MESSAGE CREATION / PARSING
#

class PartType(Enum):
    INVALID = 0
    HEADER = 1
    BODY = 2
#endclass

class PartFormat(Enum):
    INVALID = 0
    JSON = 1
    STRING = 2
    BINARY = 3
#endclass

def pack_part(part_type : PartType, part_format : PartFormat, compress : bool, buf : bytes):
    hdr = struct.pack(">BBBBI",
                      part_type.value,
                      part_format.value,
                      int(compress),
                      0,
                      len(buf))
    return hdr + buf
#enddef

def unpack_part(packed_buf):
    (type_val, format_val, compress, _, sz) = struct.unpack(">BBBBI", packed_buf[:8])
    buf = packed_buf[8:8+sz]
    return ({"type" : PartType(type_val),
             "format" : PartFormat(format_val),
             "compress" : bool(compress),
             "buf" : buf},
            sz+8)
#enddef

class MessageMethod(Enum):
    GET = 0
    POST = 1
    PATCH = 2
    COMMAND = 3
    DELETE = 4
#endclass

def create_req_header(reqid, method, path, headers):
    return {
        "requestId" : reqid,
        "type" : "request",
        "path" : str(path),
        "method" : str(method),
        "headers" : headers
    }
#enddef

def _do_pack_message(req_header, body, compress=False):
    req_header_bytes = json.dumps(req_header).encode(encoding="UTF-8")
    body_bytes = json.dumps(body).encode(encoding="UTF-8")
    if compress:
        req_header_bytes = zlib.compress(req_header_bytes)
        body_bytes = zlib.compress(body_bytes)
    #endif
    packed_hdr = pack_part(PartType.HEADER, PartFormat.JSON, False, req_header_bytes)
    packed_body = pack_part(PartType.BODY, PartFormat.JSON, compress, body_bytes)
    return packed_hdr + packed_body
#enddef

def pack_message(reqid, path, method : MessageMethod, payload, headers, compress):
    match method:
        case MessageMethod.GET | MessageMethod.POST:
            req_header = create_req_header(
                reqid,
                method.name,
                path,
                headers
            )
            return _do_pack_message(req_header, payload, compress=compress)
        case _:
            raise NotImplementedError("Method {!r} not supported.".format(method))
    #endmatch
#enddef

def unpack_message(packed_buf):

    def _process_part_buf(part_info):
        match part_info["format"]:
            case PartFormat.JSON:
                buf = part_info["buf"]
                if part_info["compress"]: buf = zlib.decompress(buf)
                return json.loads(buf)
            case _:
                raise NotImplementedError("Part format {!r} not supported.".format(part_info["format"]))
        #endmatch
    #enddef

    (hdr_part_info, read_size) = unpack_part(packed_buf)
    (body_part_info, _) = unpack_part(packed_buf[read_size:])

    assert hdr_part_info["type"] == PartType.HEADER   
    assert body_part_info["type"] == PartType.BODY

    return (_process_part_buf(hdr_part_info),
            _process_part_buf(body_part_info))
    
#enddef


#
# BLE CONNECTION
#

State = Enum("State", ("INIT", "AUTH_SENDKEY", "AUTH_WAIT_OK", "READY"))

class UnifiBleClient(object):

    def __init__(self, addr, service_uuid, auth_key=None):
        self.addr = addr
        self.client = bleak.BleakClient(self.addr)
        self.service_uuid = service_uuid
        self.service = None
        self.read_csc = None
        self.write_csc = None

        self.seqno = 0
        self.device_seqno = 0

        # Setup keys
        self.recv_key = DEFAULT_KEY
        self.send_key = DEFAULT_KEY
        self.auth_key = auth_key

        (self.dh_priv_key, self.dh_pub_key) = gen_dh_keypair()
        self.computed_key = None

        self.pkt_q = asyncio.Queue()
        
        self.state = State.INIT
        
        self.auth_complete = asyncio.Event()

        self._recv_buf = b""

        self.msg_reqid = 0
        self._request_map = {}

        # Start queue processing task.
        self.process_q_task = asyncio.get_event_loop().create_task(self._process_queue())
        
    #enddef

    def _notify_callback(self, sender, in_buf):
        DBG("Hit _notify_callback.")
        DBG("\tsender = {!r}, in_buf = {!r}".format(sender, in_buf))

        buf = self._recv_buf + in_buf
        DBG("\tbuf = {!r}".format(buf))
        
        # Peek at buffer size.
        assert len(buf) > 2
        total_size = peek_ble_packet_size(buf)
        DBG("\tExpecting packet size {}".format(total_size))
        if len(buf) < total_size:
            # We're missing data, wait for more to come in.
            self._recv_buf = buf
            DBG("\tOnly have {} bytes so far, waiting for more.".format(len(buf)))
            return
        elif len(buf) > total_size:
            DBG("\tReceived extra {} bytes, throwing away: {!r}".format(len(buf) - total_size, buf[total_size:]))
            self._recv_buf = b""
            buf = buf[:total_size]
        else:
            DBG("\tReceived exactly enough data.")
            self._recv_buf = b""
        #endif
        DBG("\tEnough data, parse packet.")
        (received_seqno, pkt_data) = self._parse_packet(buf)
        DBG("\tparsed pkt_data = {!r}".format(pkt_data))
        DBG("\tAdding to queue.")
        self.pkt_q.put_nowait((sender, received_seqno, pkt_data))
    #enddef

    async def _process_queue(self):
        def LOG(s): DBG("_process_queue: " + s)

        while True:
            (sender, received_seqno, pkt_data) = await self.pkt_q.get()
            LOG("Received packet in run loop.")
            LOG("\tstate = {!r}".format(self.state))
            LOG("\tsender = {!r}, seqno = {!r}, pkt_data = {!r}".format(sender, received_seqno, pkt_data))
        
            match self.state:
                case State.AUTH_SENDKEY:
                    # We're expecting a DiffieHelmanPacket in return
                    device_pubkey = unpack_dh_pubkey(pkt_data)
                    LOG("\tGot device pubkey: {!r}".format(device_pubkey))
                    self._compute_dh_secret_key(device_pubkey)
                    LOG("\tComputed secret key: {!r}".format(self.computed_key))
                    DINFO("Received device pubkey and computed secret key, waiting for AuthPacket.")
                    self.state = State.AUTH_WAIT_OK
                case State.AUTH_WAIT_OK:
                    # We're expecting an AuthPacket
                    if unpack_auth_ok_packet(pkt_data):
                        LOG("Auth suceeded.")
                        self.recv_key = self.computed_key
                        await self._send_packet(pack_auth_ok_packet(), 0)
                        LOG("Setting keys.")
                        self.send_key = self.computed_key
                        self.state = State.READY
                        DINFO("AuthPacket received, keys set, authentication complete.")
                        self.auth_complete.set()
                    #endif

                case State.READY:
                    if received_seqno in self._request_map:
                        LOG("Process response to request with seqno {}".format(received_seqno))
                        req_info = self._request_map[received_seqno]
                        req_info["response"] = unpack_message(pkt_data)
                        LOG("\tParsed response: {!r}".format(req_info["response"]))
                        LOG("\tTriggering event.")
                        req_info["event"].set()
                    else:
                        DWARN("_process_queue: Received seqno {}, but not in request map!".format(received_seqno))
                        LOG("\tself._request_map = {!r}".format(self._request_map))
                    #endif
                case _:
                    DWARN("_process_queue: In unknown state {!r}, ignoring packet!".format(self.state))
            #endmatch
        #endwhile
    #enddef

    def _compute_dh_secret_key(self, device_pub_key):
        keymix = nacl.bindings.crypto_scalarmult(self.dh_priv_key, device_pub_key)
        hashstate = nacl.bindings.crypto_generichash_blake2b_init()
        nacl.bindings.crypto_generichash_blake2b_update(hashstate, keymix)
        nacl.bindings.crypto_generichash_blake2b_update(hashstate, self.dh_pub_key)
        nacl.bindings.crypto_generichash_blake2b_update(hashstate, device_pub_key)
        if self.auth_key != None:
            nacl.bindings.crypto_generichash_blake2b_update(hashstate, self.auth_key)
        #endif
        self.computed_key = nacl.bindings.crypto_generichash_blake2b_final(hashstate)
    #enddef
    
    def _create_packet(self, data, protocol):
        seqno = self.seqno
        out = pack_ble_packet(data, protocol, seqno, self.send_key)
        self.seqno += 1
        DBG("Created packet: {!r}".format(out))
        return (seqno, out)
    #enddef

    def _parse_packet(self, buf):
        (received_seqno, _, pkt_data) = unpack_ble_packet(buf, self.device_seqno, self.recv_key)
        self.device_seqno = received_seqno + 1
        DBG("_parse_packet: received_seqno = {}".format(received_seqno))
        return (received_seqno, pkt_data)
    #enddef    
   
    async def _send_packet(self, pkt_data, protocol):
        (seqno, data) = self._create_packet(pkt_data, protocol)
        await self.client.write_gatt_char(self.write_csc, data, response=True)
        return seqno
    #enddef

    async def connect(self):
        await self.client.connect()
        DINFO("BLE layer connected.")
        self.service = self.client.services.get_service(self.service_uuid)
        self.read_csc = self.service.get_characteristic(READ_UUID)
        self.write_csc = self.service.get_characteristic(WRITE_UUID)

        await self.client.start_notify(self.read_csc, self._notify_callback)
        DINFO("Started notify.")
        
    #enddef

    async def disconnect(self):
        await self.client.disconnect()
    #enddef
   
    async def send_public_key(self):
        DINFO("Sending public key.")
        # Change state before sending as the notify code might run before we
        # return from the coroutine below.
        self.state = State.AUTH_SENDKEY
        await self._send_packet(pack_dh_pubkey(self.dh_pub_key), 0)
    #enddef
  
    async def connect_and_auth(self):
        DINFO("Attempting to connect and authenticate to device.")
        await self.connect()
        await self.send_public_key()
        await self.auth_complete.wait()
        DINFO("Connection established and authenticated.")
    #enddef

    async def request(self, path,
                      method=MessageMethod.GET,
                      payload=None,
                      headers=None,
                      compress=False):
        
        reqid = self.msg_reqid
        self.msg_reqid +=1 

        DINFO("Building request with reqid = {}".format(reqid))
        msg_buf = pack_message(reqid, path, method, payload, headers, compress)

        seqno = await self._send_packet(msg_buf, 3)
        DINFO("Sent packet, seqno = {}".format(seqno))
        
        req_info = {
            "response" : None,
            "event" : asyncio.Event()
        }
        self._request_map[seqno] = req_info

        DINFO("Waiting for response.")
        await req_info["event"].wait()

        DINFO("Event triggered, retreiving response.")
        DBG("\tresponse = {!r}".format(req_info["response"]))
        return req_info["response"]
        
    #enddef
    
#enddef

#
# FRONTEND
#

async def do_config_wifi(addr, service_uuid, args):

    ubc = UnifiBleClient(addr, service_uuid)
    
    await ubc.connect_and_auth()

    DINFO("Sending management payload containing WiFi credentials.")

    manage_payload = {
        "mgmt" : {
            "hosts" : [],
            "protocol" : "http",
            "token" : "XXXXXXXXXXXX",
        },
        "wifi" : {
            "ssid" : args.ssid,
            "password" : args.password,
        }
    }

    (hdr, data) = await ubc.request(
        "/api/1.2/manage",
        method=MessageMethod.POST,
        payload=manage_payload
    )

    if hdr["status"] != 200:
        DWARN("Invalid status in response from device: {}".format(hdr["status"]))
        DINFO("Full response header: {!r}".format(hdr))
        return 1
    #endif

    DINFO("Successfully sent WiFi credentials.")
    return 0
    
#enddef

async def do_ap_list(addr, service_uuid, args):

    ubc = UnifiBleClient(addr, service_uuid)
    
    await ubc.connect_and_auth()

    DINFO("Retrieving AP list.")

    (hdr, data) = await ubc.request("/api/1.2/ap")

    if hdr["status"] != 200:
        DWARN("Invalid status in response from device: {}".format(hdr["status"]))
        DINFO("Full response header: {!r}".format(hdr))
        return 1
    #endif

    if args.csv:
        fmtstr = "{},{},{}"
    else:
        fmtstr = "{:30} {:4} {:2}"
        print(fmtstr.format("SSID", "Enc", "Signal"))
        print(fmtstr.format("----", "---", "------"))
    #endif
    
    print("\n".join((
        fmtstr.format(
            ap["essid"],
            ap["encryption"],
            ap["signalLevel"])
        for ap
        in data["apList"]
    )))
    return 0
        
#enddef

async def do_auto_detect_service_uuid(args):

    scanner = bleak.BleakScanner()

    DINFO("Discovering Bluetooth devices...")
    devs = await scanner.discover()

    filtered_devs = [d for d in devs if d.address.lower() == args.address.lower()]
    if filtered_devs == []:
        raise CannotFindDeviceExn("Could not find device with address {}".format(args.address))
    elif len(filtered_devs) > 1:
        raise MultipleDevicesExn("Multiple devices with address {}".format(args.address))
    #endif
    dev = filtered_devs[0]
    DINFO("Found device.")

    for (model_name, info) in DEVICE_MAP.items():
        if dev.name.startswith(info["bt_name_prefix"]):
            DINFO("Detected device as having model '{}'".format(model_name))
            uuids = dev.details["props"]["UUIDs"]
            if info["service_uuid"].lower() in (u.lower() for u in uuids):
                DINFO("Expected service UUID present.")
            else:
                DWARN("Did not find expected service UUID {}".format(info["service_uuid"]))
            #endif
            return info["service_uuid"]                
        #endif
    #endfor

    raise CannotAutoDetectModelExn("Failed to auto-detect device model.")
    
#enddef

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="UniFi BLE client.",
    )

    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Be verbose.")

    parser.add_argument("address",
                        type=str,
                        help="Bluetooth address of UniFi device.")

    parser.add_argument("-m", "--model",
                        choices=list(DEVICE_MAP.keys()) + ["auto"],
                        default="auto",
                        help="Device model (set to auto for detection based on Bluetooth device name, default)")
    
    parser.add_argument("-u", "--service-uuid",
                        type=str,
                        help="Custom service UUID to use.")
    
    subparsers = parser.add_subparsers(required=True,
                                       dest="subcmd",
                                       title="subcommands",
                                       metavar="subcommand")
    
    parser_wifi = subparsers.add_parser("config-wifi",
                                        help="Configure device WiFi settings")
    parser_wifi.add_argument("-s", "--ssid",
                             type=str,
                             required=True,
                             help="WiFi SSID")
    parser_wifi.add_argument("-p", "--password",
                             type=str,
                             required=True,
                             help="WiFi password")
    parser_wifi.set_defaults(func=do_config_wifi)

    parser_aplist = subparsers.add_parser("ap-list",
                                          help="Retrieve AP list.")
    parser_aplist.add_argument("-C", "--csv",
                               action="store_true",
                               help="Output as plain CSV.")
    parser_aplist.set_defaults(func=do_ap_list)
    
    args = parser.parse_args()

    logging.basicConfig()
    if args.verbose:
        LOG.setLevel(logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
    #endif

    loop = asyncio.get_event_loop()

    # Get device info first.

    addr = args.address

    if args.service_uuid != None:
        service_uuid = args.service_uuid
    elif args.model == "auto":
        try:
            service_uuid = loop.run_until_complete(do_auto_detect_service_uuid(args))
        except CannotAutoDetectModelExn as exn:
            DERROR("Failed to automatically detect device model. Please specify model or service UUID manually.")
            return 1
        #endtry
    else:
        service_uuid = DEVICE_MAP[args.model]["service_uuid"]
    #endif

    DINFO("Using device address {}, service_uuid {}".format(addr, service_uuid))
    
    try:
        return loop.run_until_complete(args.func(addr, service_uuid, args))
    except KeyboardInterrupt:
        DINFO("Interrupted, exiting.")
        return 1
    except Exception as exn:
        DWARN("Exception while running subcommand: {!r}".format(exn))
        return 1
    #endtry

#enddef

if __name__ == "__main__":
    sys.exit(main())
#endif
