# -*- coding: utf-8 -*-
"""Network Explorer Module

Developed in fulfillment of the requirement defined on
https://ciscosales.instructure.com/courses/56/assignments/3313?module_item_id=4765, the present module retrieves
information about network given the range of devices IPs and the password (communityString) for SNMP access.

Examples:
    - Running the module with default arguments:

      $ python projectLauncher.py

      or

      $ python projectLauncher.py -f --range /file_location/range_filename --password /file_location/password_filename

      or

      $ python projectLauncher.py -f --range /file_location/range_filename
      Password(Input hidden):

      or

      $ python projectLauncher.py --range 192.168.0.1#25 -f --password /file_location/password_filename

      or
      $  python projectLauncher.py --range 192.168.0.1#25
      Password(Input hidden):

      or

      $ python projectLauncher.py --range 192.168.0.1#25 --password public

Attributes:
    devices_data ([]str): list of all `reachable_ips` SNMP extracted data with respect to `oid_of_interests`
        and `password`

    password (str): validated communityString for SNMP extraction from the list `passwords` or just the value
         passed from the CLI

    passwords (str): is a list of candidate strings used by SNMP as the communityString(name) to query managed devices.
        (passed as on the examples above, thougth the command line, default ranges are given in the password.txt
        file in the direction where the script is located). Once one string from the list is validated, it is set to
        the `password` attribute.

    oid_of_interests ([]str):  list of SNMP oid we would like to extract from devices in order to build the final report

    ranges (str): can be either an ip range  or a list of ip ranges (passed as on the examples
        above, thougth the command line, default ranges are given in the range.txt file in the direction where
        the script is located). valid_range = valid_ip + "#" + x, 0<x<255. (eg. 192.168.0.1#52)

    reachable_ips ([]str): list of all devices that are reachable thanks to IP ranges providen to the program

"""

try:
    import subprocess
    import sys
    import argparse
    import getpass
    import paramiko
    import re
    import time
    from colorama import init, deinit, Fore, Style
   # import matplotlib.pyplot as matp
    import networkx as nx
    from pysnmp.entity.rfc3413.oneliner import cmdgen
except ImportError:
    print "Please Make sure to install all the required packages: \n[ subprocess, sys, argparse, getpass, " \
          "matplotlib, networkx, pysnmp ]"
    sys.exit()

password = ''
"""str:  The validated password for SNMP 

This should hold a valid communityString 
"""
passwords = []
"""[]str:  Stores the list of all candidate passwords 

Always retrieved from a text file, else it is be empty
"""
ranges = []
"""[]str: Accumulator of all ser provided ranges of IPs

Always retrieved from a text file, else it is be empty
"""
reachable_ips = []
"""[]str: List of devices available 

This list is made of IPs which responds to a ping request
"""
devices_data = []
"""[]str: container of all the OID data retrieved from SNMP 

"""

oid_of_interests = '1.3.6.1.2.1.1.1.0'

"""[]str: List of OIDs of a particular interest in order to fulfill the project requirements

"""

def check_snmp_support(ip_address, community_string, list_oid_of_interests):
    """ Function to check SNMP support

    Given an IP address and a community string, performs an snmp extract

    Args:
        ip_address (str): A valid ip address. eg. 10.0.0.1
        community_string (str): An SNMP communityString. Should match the remote host's settings
        list_oid_of_interests ([]str): List of all the OIDs for which one would like to extract data with SNMP
    Returns:
        Values from cmdgen.CommandGenerator().getCmd() of pysnmp module
    Raises:
        NameError: Due to wrong module call/loading
        Exception: Any kind of exception due to pysnmp module usage

    """
    try:
        print Fore.GREEN + Style.BRIGHT + "* Checking for SNMP support on : %s\n" % ip_address
        (error, error_status, idx, var_binds) = cmdgen.CommandGenerator().getCmd(
            cmdgen.CommunityData(community_string, mpModel=0), cmdgen.UdpTransportTarget(
                (ip_address, 161), timeout=30, retries=0), list_oid_of_interests, lookupNames=True, lookupValues=True)
        if error:
            raise Exception(error)
        if error_status:
            raise Exception(error_status.prettyPrint())

        print Fore.GREEN + Style.BRIGHT + "* Host %s has SNMP Support" % ip_address

        return error, error_status, idx, var_binds
    except NameError:
        print Fore.RED + Style.BRIGHT + "* No SNMP Support on host %s. " \
                                        "or pysnmp module not installed on your system" % ip_address
        return error, error_status, idx, var_binds
    except Exception as ioe:
        print Fore.RED + Style.BRIGHT + "* No SNMP Support on host %s \n " % ip_address, ioe
        return error, error_status, idx, var_binds


def list_reachable_ips(start_ip_bytes, nbr_host):
    """Function to list reachable IPs

    Returns all reachable IPs starting from the `start_ip` and incrementally with respect to `nbr_host`

    Args:
        start_ip_bytes ([]str) : the first IP address in the given range
        nbr_host ([]str): The number of hosts in the range

    Returns:
        ip_list: The list of all reachable ips

    """
    ip_list = []
    for i in range(int(start_ip_bytes[3]), int(start_ip_bytes[3])+int(nbr_host)):
        check_ip = start_ip_bytes[0] + "." + start_ip_bytes[1] + "." + start_ip_bytes[2] + "." + str(i)
        print Fore.GREEN + Style.BRIGHT + "\n* Pinging IP : %s ... " % check_ip
        ping_reply = subprocess.call(['ping', '-c', '3', '-W', '1', '-q', '-n', check_ip], stdout=subprocess.PIPE)
        if ping_reply == 0:
            print Fore.GREEN + Style.BRIGHT + "\n* Reached IP: %s" % check_ip
            ip_list.append(check_ip)
        elif ping_reply == 2:
            print Fore.RED + Style.BRIGHT + "\n* No response from the device %s." % check_ip

        else:
            print Fore.RED + Style.BRIGHT + "\n* Unreachable device with ip %s : " % check_ip
            print "\n"
    return ip_list


def check_iprange_and_retrieve_available_ips(list_of_ranges):
    """Function to Check IP Ranges and Retrieve  available IPs

    Checks for valid IP ranges in the given parameter and retrieves all the available IPs.
    A valid range consists of a valid IP address excluding all reserved addresses, followed by a `#`
    character and a number X so that the sum of the last byte of the IP in front and X is less than 255
    eg. 10.45.24.3#23 (means from 10.45.24.3 - 10.45.24.26)

    Args:
        list_of_ranges: List of all IP ranges Candidates
    """
    for ip_range in list_of_ranges:
        ip_bytes = ip_range.split('.')
        hosts_ranges = ip_bytes[3].split("#")
        ip_bytes[3] = hosts_ranges[0]

        if (len(ip_bytes) == 4) and (1 <= int(ip_bytes[0]) <= 223) and (int(ip_bytes[0]) != 127) and (
                int(ip_bytes[0]) != 169 or int(ip_bytes[1]) != 254) and (
                0 <= int(ip_bytes[1]) <= 255 and 0 <= int(ip_bytes[2]) <= 255 and 0 <= int(ip_bytes[3]) <= 255) and (
                int(hosts_ranges[1]) + int(hosts_ranges[0]) <= 254):
            print Fore.BLUE + Style.BRIGHT + '\n* Found a valid IP range:', ip_range
            print Fore.BLUE + Style.BRIGHT + '\n* Retrieving the list of available hosts'
            reachable_ips.extend(list_reachable_ips(ip_bytes, hosts_ranges[1]))

        else:
            print Fore.GREEN + Style.BRIGHT + '\n* Found an non valid range: %s ' % ip_range
            print Fore.GREEN + Style.BRIGHT + '. Skipping...\n'


def load_configuration():
    """
    Loads ranges and passwords configurations as provided by the user using CLI flags or
    tries to use the sample ones from the script directory

    Returns:
        return_passwords ([]str): A list of candidate passwords from the user defined file
        return_password (str): Is set in case the password was entered from the CLI
        return_ranges ([]str): A list of candidate network IP ranges form a user provided file
    """
    option_parser = argparse.ArgumentParser(description="Retrieves the network topology, "
                                                        "all its devices and their interfaces information")

    option_parser.add_argument('--range', '-r', dest='range_arg',
                               help='Enables to pass the IPs range in a form of W.X.Y.Z#A, eg. 192.168.0.1#10. '
                                    'Preceded by a `-f` flag, it takes a file which should contain IP ranges\n')
    option_parser.add_argument('--password', '-p', dest='pwd_arg',
                               help='Takes a password string used as a CommunityString by SNMP. ' +
                                    'Preceded by a `-f` flag, it takes a file which should contain.' +
                                    'If omitted given the flag `--range` one will be prompted for a hidden password.' +
                                    'If the given value is empty, the program attempts to acquire a password from ' +
                                    'the password.txt file in the directory where projectLauncher.py is located.\n'
                               )
    option_parser.add_argument('-f', '--file', dest='from_f',
                               help='Enables to read ranges and passwords values from given files on the CLI.' +
                                    'Should be followed by `--range | -r` or `--password | -p` flags\n')

    args = option_parser.parse_args()
    return_one_password = ''
    return_passwords = []
    return_ranges = []

    try:
        if args.pwd_arg:
            if args.from_f:
                with open(args.pwd_arg, "r") as passwords_file:
                    return_passwords = passwords_file.readlines()
                passwords_file.close()
            else:
                return_one_password = args.pwd_arg
        elif args.range_arg:
            return_one_password = getpass.getpass()
        else:
            with open('password.txt', "r") as passwords_file:
                return_passwords = passwords_file.readlines()
            passwords_file.close()
    except (IOError, getpass.GetPassWarning) as ioe:
        print ioe
    try:
        # Open the range.txt file to load the network ranges
        if args.range_arg:
            if args.from_f:
                with open(args.range_arg, "r") as ranges_file:
                    return_ranges = ranges_file.readlines()
                ranges_file.close()
            else:
                return_ranges.append(args.range_arg)
        else:
            with open('range.txt', "r") as ranges_file:
                return_ranges = ranges_file.readlines()
            ranges_file.close()
    except IOError as ioe:
        print ioe
    return return_passwords, return_one_password,  return_ranges

def devices_information(ip_addresses):
    """
    Function which extracts the information about devices provided in the ip_addresses list.
    The provided information is as follows:
    1. Managements ip address
    2. Information about OS running on the device
    3. Password
    4. Hardware information
    5. Modules avaliable on the device

    Before using make sure that SSH is enabled on the device.
    
    :param ip_addresses: list of strings - ip addresses of the devices
    :return: dictionary with information described above
    """
    devices = []
    
    username = 'admin'
    password_filename = 'password.txt'
    
    # loading the list of possible passwords
    password_file = open(password_filename, 'r')  
    password_file.seek(0)
    passwords = password_file.readlines()
    passwords = [password.strip('\n') for password in passwords]
    password_file.close()
    
    passwrd = ''
    hardware_info = ''
    modules= []
    os_info = []
    
    for ip in ip_addresses:
    
        print '--- Attempting paramiko connection to: ', ip, ' ---'

        # create paramiko session
        ssh_client = paramiko.SSHClient()

        # must set missing host key policy since we don't have the SSH key
        # stored in the 'known_hosts' file
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # searching for the right password
        for password in passwords:
            time.sleep(10)
            try:
                print password
                ssh_client.connect(ip,
                            username=username,
                            password=password)
                passwrd = password
            except paramiko.ssh_exception.AuthenticationException:
                continue
            break
    
        print 'Success! connecting to: ', ip
    
        # retriving all desired information
        stdin, stdout, ssh_stderr = ssh_client.exec_command('show hardware')
        show_hardware = stdout.read()
        
        hardware_pattern = re.compile('.*(processor).*\(revision.*\)')
        hardware_info = hardware_pattern.search(show_hardware).group(0)
    
        os_type_pattern = re.compile('.*(NX\-OS|IOS|IOS\-XR).*,.*,')
        os_info = os_type_pattern.search(show_hardware).group(0)[:-1]
    
        ssh_client.connect(ip,
                            username=username,
                            password=passwrd)
        stdin, stdout, ssh_stderr = ssh_client.exec_command('show inventory')
        show_inventory = stdout.read()
        show_inventory = show_inventory.split("\n\r")
    
        
        inventory_pattern = re.compile('(NAME: \".*\",)')
        for line in show_inventory:
            try:
                modules.append(inventory_pattern.search(line).group(0)[7:-2])
            except:
                pass
            
        print '------------------------------------------------------'
        print ' Management ip address: ', ip
        print '        OS information: ', os_info
        print '              Password: ', passwrd
        print '  Hardware information: ', hardware_info
        print '   Modules information:'
        for mod in modules:
            print '                        ', mod
        print '------------------------------------------------------\n'
    
        devices.append({'ip': ip,
                        'os_info': os_info,
                        'password': passwrd,
                        'hardware_info': hardware_info,
                        'modules_info': modules})
        
    return devices

init()

try:

    print Style.BRIGHT + "\n################### LOADING CONFIGURATIONS... ###################"
    passwords, password, ranges = load_configuration()
    check_iprange_and_retrieve_available_ips(ranges)

    print Style.BRIGHT + "\n################ FULFILLING PROJECTS REQUIREMENTS ################"

    # For each specific task, for instance listing interfaces, modules, or os version,
    # one can achieve that by passing specific oids, see https://tools.ietf.org/html/rfc1213

    try:
        for ip in reachable_ips:
            if not password:
                for pwd in passwords:
                    pwd = pwd.rstrip('\n\r')
                    errorIndication, errorStatus, _, varBindNbrTable = check_snmp_support(ip, pwd, oid_of_interests)
                    if not errorIndication and not errorStatus:
                        password = pwd
                        print Fore.GREEN + Style.BRIGHT + "* Found a matching password from the provided file ", pwd

                        print Fore.GREEN + Style.BRIGHT, varBindNbrTable[0][1].prettyPrint()
                        break
                    else:
                        print Fore.RED + Style.BRIGHT + "FAILED WITH ERROR: ", errorIndication, errorStatus
                        continue
            else:
                errorIndication, errorStatus, errorIndex, varBindNbrTable = \
                    check_snmp_support(ip, password, oid_of_interests)
                if errorIndication:
                    print errorIndication
                if errorStatus:
                    print errorStatus.prettyPrint()
                else:
                    # TODO Here process the returned tables in varBindNbrTable
                        print Fore.GREEN + Style.BRIGHT, varBindNbrTable
    except Exception as e:
        print e
except KeyboardInterrupt:
    print Fore.CYAN + Style.BRIGHT + "\nExecution aborted by the user"
    sys.exit()

deinit()
