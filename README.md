# LeAmitVPN
Simple VPN client and server implementations in python.

## Dependencies

```shell
sudo apt-get install python-dev python-scapy
sudo pip install python-pytun pycrypto
```

## Architecture

                                    +---------------------------------+
                                    |                                 |
                                    |   10.10.0.1   VPN Server        |
                                    |   Server                        |
                                    |                                 |
                            +-------+---------------------------------+--------+
                            |                                                  |
                            |                                                  |
                            |                                                  |
                            |                                                  |
                            |                                                  |
                            |                                                  |
                            |                                                  |
+---------------------------v----+                                      +------v-------------------------+
|                                |                                      |                                |
|   10.10.0.2  Web Server        |                                      |   10.10.0.3   Openssh Server   |
|   Kiwi                         |                                      |   Pa                           |
|                                |                                      |                                |
|                                |                                      |                                |
+--------------------------------+                                      +--------------------------------+





                   +                                           +
                   |  Encrypt(Poll(username, password,         |
                   |  timestamp)                               |
                   |                                           |
                   +------------------------------------------>+
                   |                                           |
                   |                                           |
                   |                                           |
                   |                                           |
                   |                                           |
                   | <-----------------------------------------+
                   |                                           |
                   |           Encrypt(Messages)               |
                   |                                           |
                   |                                           |
                   |                                           |
                   +                                           +


## Client

```shell
sudo python client.py --tun-adr 10.10.0.2 --tun-dstaddr 10.10.0.1 --pw password
```

## Server

```shell
sudo python server.py
```

Our server is present at (prashant.at)[prashant.at].


## License
Copyright 2017 Prashant Anantharaman, Kirtivardhan Rathore, Aditi Phatak

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
