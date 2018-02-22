# Python-project

```bash

-------------------------------------------------------------------------
                    NETWORK DISCOVERY EXECUTION 
-------------------------------------------------------------------------


usage: projectpython.py [-h] [--range RANGE_ARG] [--password PWD_ARG]
                        [--token TOKEN_ARG] [--ciscouser CISCO_ARG]
                        [--ciscosecret SECRET_ARG] [-f FROM_F]

Retrieves the network topology, all its devices and their interfaces
information

optional arguments:
  -h, --help            show this help message and exit
  --range RANGE_ARG, -r RANGE_ARG
                        Enables to pass the IPs range in a form of W.X.Y.Z#A,
                        eg. 192.168.0.1#10. Preceded by a `-f` flag, it takes
                        a file which should contain IP ranges
  --password PWD_ARG, -p PWD_ARG
                        Takes a password string used as a CommunityString by
                        SNMP. Preceded by a `-f` flag, it takes a file which
                        should contain.If omitted given the flag `--range` one
                        will be prompted for a hidden password.If the given
                        value is empty, the program attempts to acquire a
                        password from the password.txt file in the directory
                        where projectLauncher.py is located.
  --token TOKEN_ARG, -t TOKEN_ARG
                        A String token needed for retrieval of EoL/EoS
                        informations from apiconsole.cisco.com access
  --ciscouser CISCO_ARG, -c CISCO_ARG
                        if no `token` (--token | -t flag) was provided one can
                        specify a cisco ClientID and then provide its attached
                        secret for login
  --ciscosecret SECRET_ARG, -s SECRET_ARG
                        The secret for the Cisco ClientID passed by
                        `--ciscouser | -c` flag
  -f FROM_F, --file FROM_F
                        Enables to read ranges and passwords values from given
                        files on the CLI.Should be followed by `--range | -r`
                        or `--password | -p` flags

```

The present project is designed to fulfill the requirements stated [here](https://ciscosales.instructure.com/courses/56/assignments/3313?module_item_id=4765)

### Practical Example

#### Topology

 ![Topology.png](https://raw.github.com/MagdaRyb/Python-project/master/static-content/Topology.png)
 
#### Configurations

In order to test the present, one should refer to [the configuration files](https://github.com/MagdaRyb/Python-project/tree/master/static-content)
 or provide  a personalized topology, configs, passwords and range files

#### Python Version

```bash
$ python --version 
Python 2.7.14
```

#### Dependencies to be installed

```bash
$ python -m pip install pysnmp  
$ python -m pip install matplotlib  # Not in use
$ python -m pip install networkx    # Not in use
$ python -m pip install setuptools  
$ python -m pip install colorama    # For styled printing
$ python -m pip install requests

```

#### How to test 

To test the present, make sure to be connected to the network you would like to query. 
- Setup SNMP on these devices  with a Community String that you will add to the [password.txt](https://raw.github.com/MagdaRyb/Python-project/master/password.txt) file
- Add the range of IPs used in the network in the [range.txt](https://raw.github.com/MagdaRyb/Python-project/master/range.txt) file 
- Execute one of the command given below  
    ```bash
   $ python projectLauncher.py
   $ python projectLauncher.py -f --range /file_location/range_filename --password /file_location/password_filename
   $ python projectLauncher.py -f --range /file_location/range_filename
   Password:
   $ python projectLauncher.py --range 192.168.0.1#25
   Password:
   $ python projectLauncher.py --range 192.168.0.1#25 -f --password /file_location/password_filename
   $ python projectLauncher.py --range 192.168.0.1#25 --password public
    ```

#### What's next?

See the module [documentation](http://htmlpreview.github.com/?https://github.com/MagdaRyb/Python-project/blob/master/static-content/Docs/ciscoIncubatorProjectGroup11.html)

Sample Output file:

```json
﻿-----------------------------------START-----------------------------------
{
    "192.168.2.102": {
        "device_hardware_os_information": {
            "hardware_info": "Cisco 7206VXR (NPE400) processor (revision A)",
            "ip": "192.168.2.102",
            "modules_info": {
                "Chassis": {
                    "SN": "11111111",
                    "description": "Cisco 7206VXR, 6-slot chassis",
                    "end_of_life_or_end_of_service": {
                        "EOXRecord": [
                            {
                                "EOLProductID": "PWR-SCE-AC=",
                                "EOXExternalAnnouncementDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2012-10-01"
                                },
                                "EOXInputType": "ShowEOXBySerialNumber",
                                "EOXInputValue": "11111111",
                                "EOXMigrationDetails": {
                                    "MigrationInformation": " ",
                                    "MigrationOption": "See Migration Section",
                                    "MigrationProductId": " ",
                                    "MigrationProductInfoURL": "http://www.cisco.com/en/US/products/ps9591/index.html",
                                    "MigrationProductName": " ",
                                    "MigrationStrategy": "Customers are encouraged to migrate to the Cisco SCE 8000 Series Service Control Engine. Information about this product can be found at: http://www.cisco.com/en/US/products/ps9591/index.html.",
                                    "PIDActiveFlag": "Y"
                                },
                                "EndOfRoutineFailureAnalysisDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2014-04-01"
                                },
                                "EndOfSWMaintenanceReleases": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2014-04-01"
                                },
                                "EndOfSaleDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2013-04-01"
                                },
                                "EndOfSecurityVulSupportDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": " "
                                },
                                "EndOfServiceContractRenewal": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2017-06-27"
                                },
                                "EndOfSvcAttachDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2014-04-01"
                                },
                                "LastDateOfSupport": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2018-03-31"
                                },
                                "LinkToProductBulletinURL": "http://www.cisco.com/en/US/prod/collateral/ps7045/ps6129/ps6133/ps6150/end_of_life_notice_c51-716192.html",
                                "ProductBulletinNumber": "EOL8540",
                                "ProductIDDescription": "Cisco Service Control Engine AC Power Supply",
                                "UpdatedTimeStamp": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2014-02-18"
                                }
                            }
                        ],
                        "PaginationResponseRecord": {
                            "LastIndex": 1,
                            "PageIndex": 1,
                            "PageRecords": 1,
                            "TotalRecords": 1
                        }
                    }
                },
                "NPE400 0": {
                    "SN": "4294967295",
                    "description": "Cisco 7200VXR Network Processing Engine NPE-400",
                    "end_of_life_or_end_of_service": {
                        "EOXRecord": [
                            {
                                "EOLProductID": "CISCO3662-AC",
                                "EOXExternalAnnouncementDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2003-06-02"
                                },
                                "EOXInputType": "ShowEOXBySerialNumber",
                                "EOXInputValue": "4294967295",
                                "EOXMigrationDetails": {
                                    "MigrationInformation": "3845 w/AC PWR,2GE,1SFP,4NME,4HWIC, IP Base, 64F/256D",
                                    "MigrationOption": "Enter PID(s)",
                                    "MigrationProductId": "CISCO3845",
                                    "MigrationProductInfoURL": " ",
                                    "MigrationProductName": " ",
                                    "MigrationStrategy": " ",
                                    "PIDActiveFlag": "Y"
                                },
                                "EndOfRoutineFailureAnalysisDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2004-11-30"
                                },
                                "EndOfSWMaintenanceReleases": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": " "
                                },
                                "EndOfSaleDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2003-12-31"
                                },
                                "EndOfSecurityVulSupportDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": " "
                                },
                                "EndOfServiceContractRenewal": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2007-12-31"
                                },
                                "EndOfSvcAttachDate": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2004-12-31"
                                },
                                "LastDateOfSupport": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2008-12-31"
                                },
                                "LinkToProductBulletinURL": "http://www.cisco.com/en/US/prod/collateral/routers/ps274/prod_end-of-life_notice09186a0080184884.html",
                                "ProductBulletinNumber": "2114-1",
                                "ProductIDDescription": "Dual 10/100 E Cisco 3660 6-slot Modular Router-AC with IP SW",
                                "UpdatedTimeStamp": {
                                    "dateFormat": "YYYY-MM-DD",
                                    "value": "2009-01-06"
                                }
                            }
                        ],
                        "PaginationResponseRecord": {
                            "LastIndex": 1,
                            "PageIndex": 1,
                            "PageRecords": 1,
                            "TotalRecords": 1
                        }
                    }
                },
                "Power Supply 1": {
                    "SN": null,
                    "description": "Cisco 7200 AC Power Supply"
                },
                "Power Supply 2": {
                    "SN": null,
                    "description": "Cisco 7200 AC Power Supply"
                },
                "module 0": {
                    "SN": "0",
                    "description": "I/O FastEthernet (TX-ISL)",
                    "end_of_life_or_end_of_service": {
                        "EOXRecord": [
                            {
                                "EOLProductID": "",
                                "EOXError": {
                                    "ErrorDataType": "PRODUCT_ID",
                                    "ErrorDataValue": "",
                                    "ErrorDescription": "EOX information does not exist for the following product ID(s): ",
                                    "ErrorID": "SSA_ERR_026"
                                },
                                "EOXExternalAnnouncementDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EOXInputType": "ShowEOXBySerialNumber",
                                "EOXInputValue": "0",
                                "EOXMigrationDetails": {
                                    "MigrationInformation": "",
                                    "MigrationOption": "",
                                    "MigrationProductId": "",
                                    "MigrationProductInfoURL": "",
                                    "MigrationProductName": "",
                                    "MigrationStrategy": "",
                                    "PIDActiveFlag": ""
                                },
                                "EndOfRoutineFailureAnalysisDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSWMaintenanceReleases": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSaleDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfServiceContractRenewal": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSvcAttachDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "LastDateOfSupport": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "LinkToProductBulletinURL": "",
                                "ProductBulletinNumber": "",
                                "ProductIDDescription": "",
                                "UpdatedTimeStamp": {
                                    "dateFormat": null,
                                    "value": ""
                                }
                            }
                        ],
                        "PaginationResponseRecord": {
                            "LastIndex": 1,
                            "PageIndex": 1,
                            "PageRecords": 1,
                            "TotalRecords": 1
                        }
                    }
                },
                "module 1": {
                    "SN": "0",
                    "description": "GigabitEthernet",
                    "end_of_life_or_end_of_service": {
                        "EOXRecord": [
                            {
                                "EOLProductID": "",
                                "EOXError": {
                                    "ErrorDataType": "PRODUCT_ID",
                                    "ErrorDataValue": "",
                                    "ErrorDescription": "EOX information does not exist for the following product ID(s): ",
                                    "ErrorID": "SSA_ERR_026"
                                },
                                "EOXExternalAnnouncementDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EOXInputType": "ShowEOXBySerialNumber",
                                "EOXInputValue": "0",
                                "EOXMigrationDetails": {
                                    "MigrationInformation": "",
                                    "MigrationOption": "",
                                    "MigrationProductId": "",
                                    "MigrationProductInfoURL": "",
                                    "MigrationProductName": "",
                                    "MigrationStrategy": "",
                                    "PIDActiveFlag": ""
                                },
                                "EndOfRoutineFailureAnalysisDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSWMaintenanceReleases": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSaleDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfServiceContractRenewal": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSvcAttachDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "LastDateOfSupport": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "LinkToProductBulletinURL": "",
                                "ProductBulletinNumber": "",
                                "ProductIDDescription": "",
                                "UpdatedTimeStamp": {
                                    "dateFormat": null,
                                    "value": ""
                                }
                            }
                        ],
                        "PaginationResponseRecord": {
                            "LastIndex": 1,
                            "PageIndex": 1,
                            "PageRecords": 1,
                            "TotalRecords": 1
                        }
                    }
                },
                "module 2": {
                    "SN": "0",
                    "description": "GigabitEthernet",
                    "end_of_life_or_end_of_service": {
                        "EOXRecord": [
                            {
                                "EOLProductID": "",
                                "EOXError": {
                                    "ErrorDataType": "PRODUCT_ID",
                                    "ErrorDataValue": "",
                                    "ErrorDescription": "EOX information does not exist for the following product ID(s): ",
                                    "ErrorID": "SSA_ERR_026"
                                },
                                "EOXExternalAnnouncementDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EOXInputType": "ShowEOXBySerialNumber",
                                "EOXInputValue": "0",
                                "EOXMigrationDetails": {
                                    "MigrationInformation": "",
                                    "MigrationOption": "",
                                    "MigrationProductId": "",
                                    "MigrationProductInfoURL": "",
                                    "MigrationProductName": "",
                                    "MigrationStrategy": "",
                                    "PIDActiveFlag": ""
                                },
                                "EndOfRoutineFailureAnalysisDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSWMaintenanceReleases": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSaleDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfServiceContractRenewal": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "EndOfSvcAttachDate": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "LastDateOfSupport": {
                                    "dateFormat": null,
                                    "value": ""
                                },
                                "LinkToProductBulletinURL": "",
                                "ProductBulletinNumber": "",
                                "ProductIDDescription": "",
                                "UpdatedTimeStamp": {
                                    "dateFormat": null,
                                    "value": ""
                                }
                            }
                        ],
                        "PaginationResponseRecord": {
                            "LastIndex": 1,
                            "PageIndex": 1,
                            "PageRecords": 1,
                            "TotalRecords": 1
                        }
                    }
                },
                "module 3": {
                    "SN": null,
                    "description": "GigabitEthernet"
                }
            },
            "os_info": "Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 12.4(15)T9",
            "password": "P@55w&rd"
        },
        "device_interfaces_information": {
            "FastEthernet0/0 ": {
                "interface_informations": "FastEthernet0/0 is up, line protocol is up \r\n  Hardware is DEC21140, address is ca02.0eea.0000 (bia ca02.0eea.0000)\r\n  Internet address is 192.168.2.102/24\r\n  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec, \r\n     reliability 255/255, txload 1/255, rxload 1/255\r\n  Encapsulation ARPA, loopback not set\r\n  Keepalive set (10 sec)\r\n  Half-duplex, 100Mb/s, 100BaseTX/FX\r\n  ARP type: ARPA, ARP Timeout 04:00:00\r\n  Last input 00:00:00, output 00:00:00, output hang never\r\n  Last clearing of \"show interface\" counters never\r\n  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0\r\n  Queueing strategy: fifo\r\n  Output queue: 0/40 (size/max)\r\n  5 minute input rate 0 bits/sec, 0 packets/sec\r\n  5 minute output rate 0 bits/sec, 0 packets/sec\r\n     1302 packets input, 156720 bytes\r\n     Received 84 broadcasts, 0 runts, 0 giants, 0 throttles\r\n     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\r\n     0 watchdog\r\n     0 input packets with dribble condition detected\r\n     2808 packets output, 370738 bytes, 0 underruns\r\n     0 output errors, 0 collisions, 1 interface resets\r\n     0 unknown protocol drops\r\n     0 babbles, 0 late collision, 0 deferred\r\n     0 lost carrier, 0 no carrier\r\n     0 output buffer failures, 0 output buffers swapped out\r\n"
            },
            "GigabitEthernet1/0 ": {
                "interface_informations": "GigabitEthernet1/0 is up, line protocol is up \r\n  Hardware is 82543, address is ca02.0eea.001c (bia ca02.0eea.001c)\r\n  Internet address is 192.168.12.21/24\r\n  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec, \r\n     reliability 255/255, txload 1/255, rxload 1/255\r\n  Encapsulation ARPA, loopback not set\r\n  Keepalive set (10 sec)\r\n  Full-duplex, 1000Mb/s, link type is autonegotiation, media type is SX\r\n  output flow-control is unsupported, input flow-control is unsupported\r\n  ARP type: ARPA, ARP Timeout 04:00:00\r\n  Last input 00:00:02, output 00:00:02, output hang never\r\n  Last clearing of \"show interface\" counters never\r\n  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0\r\n  Queueing strategy: fifo\r\n  Output queue: 0/40 (size/max)\r\n  5 minute input rate 0 bits/sec, 0 packets/sec\r\n  5 minute output rate 0 bits/sec, 0 packets/sec\r\n     1439 packets input, 86748 bytes, 0 no buffer\r\n     Received 26 broadcasts, 0 runts, 0 giants, 0 throttles\r\n     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\r\n     0 watchdog, 0 multicast, 0 pause input\r\n     0 input packets with dribble condition detected\r\n     1439 packets output, 86748 bytes, 0 underruns\r\n     0 output errors, 0 collisions, 1 interface resets\r\n     1 unknown protocol drops\r\n     0 babbles, 0 late collision, 0 deferred\r\n     0 lost carrier, 0 no carrier, 0 pause output\r\n     0 output buffer failures, 0 output buffers swapped out\r\n"
            },
            "GigabitEthernet2/0 ": {
                "interface_informations": "GigabitEthernet2/0 is up, line protocol is up \r\n  Hardware is 82543, address is ca02.0eea.0038 (bia ca02.0eea.0038)\r\n  Internet address is 192.168.23.23/24\r\n  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec, \r\n     reliability 255/255, txload 1/255, rxload 1/255\r\n  Encapsulation ARPA, loopback not set\r\n  Keepalive set (10 sec)\r\n  Full-duplex, 1000Mb/s, link type is autonegotiation, media type is SX\r\n  output flow-control is unsupported, input flow-control is unsupported\r\n  ARP type: ARPA, ARP Timeout 04:00:00\r\n  Last input 00:00:01, output 00:00:01, output hang never\r\n  Last clearing of \"show interface\" counters never\r\n  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0\r\n  Queueing strategy: fifo\r\n  Output queue: 0/40 (size/max)\r\n  5 minute input rate 0 bits/sec, 0 packets/sec\r\n  5 minute output rate 0 bits/sec, 0 packets/sec\r\n     1439 packets input, 86748 bytes, 0 no buffer\r\n     Received 26 broadcasts, 0 runts, 0 giants, 0 throttles\r\n     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\r\n     0 watchdog, 0 multicast, 0 pause input\r\n     0 input packets with dribble condition detected\r\n     1439 packets output, 86748 bytes, 0 underruns\r\n     0 output errors, 0 collisions, 1 interface resets\r\n     0 unknown protocol drops\r\n     0 babbles, 0 late collision, 0 deferred\r\n     0 lost carrier, 0 no carrier, 0 pause output\r\n     0 output buffer failures, 0 output buffers swapped out\r\n"
            },
            "GigabitEthernet3/0 ": {
                "interface_informations": "GigabitEthernet3/0 is up, line protocol is up \r\n  Hardware is 82543, address is ca02.0eea.0054 (bia ca02.0eea.0054)\r\n  Internet address is 192.168.26.26/24\r\n  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec, \r\n     reliability 255/255, txload 1/255, rxload 1/255\r\n  Encapsulation ARPA, loopback not set\r\n  Keepalive set (10 sec)\r\n  Full-duplex, 1000Mb/s, link type is autonegotiation, media type is SX\r\n  output flow-control is unsupported, input flow-control is unsupported\r\n  ARP type: ARPA, ARP Timeout 04:00:00\r\n  Last input 00:00:00, output 00:00:01, output hang never\r\n  Last clearing of \"show interface\" counters never\r\n  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0\r\n  Queueing strategy: fifo\r\n  Output queue: 0/40 (size/max)\r\n  5 minute input rate 0 bits/sec, 0 packets/sec\r\n  5 minute output rate 0 bits/sec, 0 packets/sec\r\n     1439 packets input, 86748 bytes, 0 no buffer\r\n     Received 26 broadcasts, 0 runts, 0 giants, 0 throttles\r\n     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\r\n     0 watchdog, 0 multicast, 0 pause input\r\n     0 input packets with dribble condition detected\r\n     1439 packets output, 86748 bytes, 0 underruns\r\n     0 output errors, 0 collisions, 1 interface resets\r\n     0 unknown protocol drops\r\n     0 babbles, 0 late collision, 0 deferred\r\n     0 lost carrier, 0 no carrier, 0 pause output\r\n"
            }
        }
    }
}
------------------------------------END------------------------------------

```