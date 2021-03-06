# packetanalyser

Packet analyser to read pcap files and parse according to given protocol such as SIP.

## Supported Operated Systems

Implementation works with Linux and MacOS

## Dependencies for Running Locally

- pip 20.1.1
- Python >= 3.8.3
- virtualenv >= 20.0.23

## Basic Build Instructions

1. Clone this repo and change to directory.
2. Create virtual env: `virtualenv .`
3. Start virtualenv : `. bin/activate`
4. Install requirements: `pip install -r requirements.txt`
5. Run it: `packetanalyser.py [-h] [-f FILE | -i IFNAME] [-c COUNT] [-t TIMEOUT] -p {sip,rtp}`.

## Running the application

```bash
./packetanalyser.py -h
usage: packetanalyser.py [-h] [-f FILE | -i IFNAME] [-c COUNT] [-t TIMEOUT] -p {sip,rtp}

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Name of file to read packets from
  -i IFNAME, --ifname IFNAME
                        Name of interface to capture live packets from
  -p {sip,rtp}, --proto {sip,rtp}
                        Name of protocol to be analysed

interface options:
  -c COUNT, --count COUNT
                        Number of packets to capture
  -t TIMEOUT, --timeout TIMEOUT
                        Lenght of time to capture
```

```bash
$./packetanalyser.py -f outbound2.pcap
Reading file outbound2.pcap
                      z9hG4bKPj4453585d-c73b-481d-88ce-90f8b3be34cf      z9hG4bKPj4397c8a4-1220-4bf3-9f21-2959810dcd1d
caller                                                     28190090                                           28190090
called                                                     37007164                                           37007164
caller_media_address                                  10.100.208.82                                      10.100.208.82
caller_sdp_media_port                                         15410                                              15410
set_up                                                       failed                                            success
set_up_response                                                 401                                                200
called_media_address                                            NaN                                        10.100.77.4
called_sdp_media_port                                           NaN                                              26876
codec                                                           NaN                                               PCMU
audio_file                                                      NaN  call_audio/z9hG4bKPj4397c8a4-1220-4bf3-9f21-29...
```

## Audio Output

Audio output of G711 calls are saved to the `call_output` directory. Calss are saved by stream direction (Incoming and Outgoing). The name will default to the _branch_ prarameter from the SIP call. Call audio is inferred during call setup exchange (`INVITE-18x-200-ACK`), if any of these messages are missing from the trace a call would not be able to be found.
