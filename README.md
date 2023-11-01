UniFi BLE Client
================

This Python module allows communication with UniFi devices that expose a
Bluetooth Low-Energy (BLE) interface for initial configuration. Normally, such
devices need to be configured using a mobile app, which will connect to the
device via BLE, and set it up to connect to a WiFi network (and subsequently
contact a controller to complete the adoption process). This client can be
used as a substitute for the mobile app, and provide the device with WiFi
credentials to get it onto the network.

## WARNING: Bluetooth Stack issues

The device I used to develop and test this code is a UniFi Protect G3 Instant
camera. Unfortunately, it turns out that the camera's firmware uses a buggy
bluetooth stack, which does not properly honour BLE MTU negotiation. It sends
data at an MTU higher than what was negotiated. **As a result, if your Bluetooth
stack is strict about the MTU (as Bluez in Linux is), connecting to the device
will not work properly.**

I circumvented this by using a patched version of `bluetoothd` which will
return as much data as can be read from the device, instead of truncating it
to the MTU value. I will try to put up a copy of the patched code
somewhere. Otherwise, the code here might or might work, depending on your
bluetooth stack, and the stack in the device you're trying to connect to.

PS: I put up an issue on the Bluez repository regarding this:
https://github.com/bluez/bluez/issues/576

## Tested Devices

Currently this script has only been tested on the following devices:

- UniFi Protect G3 Instant

If you have successfully used this module on a different device, please let me
know!

## Dependencies

```
python3 -m pip install -r requirements.txt
```

Requires `bleak`, `pynacl`, `msgpack`.

## Usage

```
$ python unifi_ble_client.py --help
usage: unifi_ble_client.py [-h] [-v] [-m {g3-instant,auto}] [-u SERVICE_UUID] address subcommand ...

UniFi BLE client.

positional arguments:
  address               Bluetooth address of UniFi device.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Be verbose.
  -m {g3-instant,auto}, --model {g3-instant,auto}
                        Device model (set to auto for detection based on Bluetooth device name, default)
  -u SERVICE_UUID, --service-uuid SERVICE_UUID
                        Custom service UUID to use.

subcommands:
  subcommand
    config-wifi         Configure device WiFi settings
    ap-list             Retrieve AP list.

```

To send WiFi credentials to a device with address `11:22:33:44:55:66`:

```
$ python unifi_ble_client.py -v "11:22:33:44:55:66" config-wifi -s "some-ssid" -p "wpa_password"
INFO:__main__:Discovering Bluetooth devices...
INFO:__main__:Found device.
INFO:__main__:Detected device as having model 'g3-instant'
INFO:__main__:Expected service UUID present.
INFO:__main__:Using device address 11:22:33:44:55:66, service_uuid 0c430d0c-00ef-4367-bc6f-ca7c51e6b61f
INFO:__main__:Attempting to connect and authenticate to device.
INFO:__main__:BLE layer connected.
INFO:__main__:Started notify.
INFO:__main__:Sending public key.
INFO:__main__:Received device pubkey and computed secret key, waiting for AuthPacket.
INFO:__main__:AuthPacket received, keys set, authentication complete.
INFO:__main__:Connection established and authenticated.
INFO:__main__:Sending management payload containing WiFi credentials.
INFO:__main__:Building request with reqid = 0
INFO:__main__:Sent packet, seqno = 2
INFO:__main__:Waiting for response.
INFO:__main__:Event triggered, retreiving response.
INFO:__main__:Successfully sent WiFi credentials.

```

To list APs available on the device:

```
(01:03:13) terry:$ python unifi_ble_client.py "11:22:33:44:55:66" ap-list
SSID                           Enc  Signal
----                           ---  ------
some_ssid                      wpa2 -72
another_ssid                   wpa2 -86
...

```

## API

The `UnifiBleClient` class included in this module can be used in your own
code to communicate with UniFi devices.

```python
ubc = UnifiBleClient(addr, service_uuid)

await ubc.connect_and_auth()

(hdr, data) = await ubc.request("/api/1.2/ap")

print("Returned status: {}".format(hdr["status"]))

print(repr(data))
```

## Protocol Specification

The work here is mostly based on reverse engineering the UniFi mobile app for
Android. A document describing the reverse-engineered protocol can be found
[here](doc/protocol.md).
