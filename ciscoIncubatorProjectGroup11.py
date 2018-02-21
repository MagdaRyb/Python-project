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
    import json
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
devices_data = {}
"""[]str: Dictionary of all the data retrieved fo a specif device 

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


def ssh_session_connector(remote_ip,  user_password, username=None):
    """"Establishes an SSH Connection

    Args:
        remote_ip (str): the IP of the remote SSH client to connect to
        user_password (str): a password to be used for connection to the selected host passed as `ip`
        username (str): an optional attribute, username which if not provided defaults in admin
    Returns:
        ssh_client (paramiko.SSHClient()): A ssh Client with a connection ready to execute commands
        ssh_connection_status (str):
    """
    if username is None:
        username = 'admin'
    print Fore.BLUE + Style.BRIGHT + '--- Attempting paramiko connection to: ', remote_ip, ' ---'
    # create paramiko session
    ssh_client = paramiko.SSHClient()
    # must set missing host key policy since we don't have the SSH key
    # stored in the 'known_hosts' file
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(remote_ip, username=username, password=user_password)
        print Fore.GREEN + Style.BRIGHT + '--- Connection to: ', remote_ip, ' established ---'
        ssh_connection_status = True
    except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception) as e:
        print Fore.RED + Style.BRIGHT + '--- SSH: Could not connect to: ', remote_ip, ' ---', e
        ssh_connection_status = False

    return ssh_client, ssh_connection_status


def ssh_session_executor(remote_ip, user_password, command_list):
    """
    Given a list of commands and client authentication data, executes and retrieves the result of these commands
    using a SSH connection

    Args:
        remote_ip (str): A IP of the remote SSH Client
        user_password (str): Password for the admin user
        command_list ([]str): a list of commands to be executed within one ssh connection
    Returns:
        ssh_connection_results ({}str): The result of the ssh command list
        ssh_stderr (str): A connection error string
    """
    try:
        ssh_connection_results = {}
        for command in command_list:
            print Fore.WHITE + Style.BRIGHT + "Executing `%s` ..." % command
            ssh_client, connexion_status = ssh_session_connector(remote_ip, user_password)
            if not connexion_status:
                raise Exception("Failed to establish an SSH Connection, while executing `%s`" % command)
            stdin, stdout, ssh_stderr = ssh_client.exec_command(command, timeout=90)
            ssh_connection_results[command] = stdout.read()
            if ssh_stderr.read().find("unconnected"):
                ssh_stderr = None
            print ssh_connection_results[command]
            print Fore.BLUE + Style.BRIGHT + "Successfully executed `%s` ..." % command
            ssh_client.close()
    except (paramiko.ssh_exception, paramiko.ssh_exception.AuthenticationException) as pe:
        print pe
    return ssh_connection_results, ssh_stderr


def get_device_information(device_ip, user_password):
    """Function which extracts the information about a device provided the `ip`.

    Before using make sure that SSH is enabled on the device.
    The provided information is as follows:
    1. Management ip address
    2. Information about OS running on the device
    3. Password
    4. Hardware information
    5. Modules avaliable on the device

    Args:
        user_password (str): password for the admin user
        device_ip (str): the IP of the device for which we want to perform the SSH Extraction
    Returns:
        device ({}): dictionary with information described above
    """
    modules = {}
    os_info = ''
    hardware_info = ''
    commands = ['show inventory', 'show hardware']
    # retriving all desired information
    stdout, ssh_stderr = ssh_session_executor(device_ip, user_password, commands)
    if ssh_stderr:
        print Fore.RED + Style.BRIGHT \
              + '--- SSH (%s): Could not execute all %s on %s:  ---' % \
              (ssh_stderr, commands, device_ip)
    show_hardware = stdout['show hardware']
    if show_hardware:
        hardware_pattern = re.compile('.*(processor).*\(revision.*\)')
        hardware_info = hardware_pattern.search(show_hardware).group(0)

        os_type_pattern = re.compile('.*(NX\-OS|IOS|IOS\-XR).*,.*,')
        os_info = os_type_pattern.search(show_hardware).group(0)[:-1]

    show_inventory = stdout['show inventory']
    if show_inventory:
        last_module_name = None
        show_inventory = show_inventory.split("\n\r")
        inventory_name__pattern = re.compile('(NAME: \".*\",)')
        inventory_desc_pattern = re.compile('(DESCR: \".*\")')
        inventory_sn_pattern = re.compile('(SN: \d+ )')
        for line in show_inventory:
            module = inventory_name__pattern.search(line)
            module_desc = inventory_desc_pattern.search(line)
            module_sn = inventory_sn_pattern.search(line)
            if module_sn and last_module_name:
                modules[last_module_name].update({"SN": module_sn.group(0)[4:-1]})
                last_module_name = ''
            elif module_sn is None and last_module_name:
                modules[last_module_name].update({"SN": None})
                last_module_name = ''
            if module:
                last_module_name = module.group(0)[7:-2]
            if module_desc:
                modules[last_module_name] = {"description": module_desc.group(0)[8:-1]}
    print '------------------------------------------------------'
    print ' Management ip address: ', device_ip
    print '        OS information: ', os_info
    print '              Password: ', password
    print '  Hardware information: ', hardware_info
    print '   Modules information:'
    for mod in modules:
        print '                        ', mod
    print '------------------------------------------------------\n'
    return {'ip': device_ip,
            'os_info': os_info,
            'password': password,
            'hardware_info': hardware_info,
            'modules_info': modules
            }


def set_password(tes_ip, list_of_passwords, validated_password=None):
    if validated_password is None or not validated_password:
        for pwd in list_of_passwords:
            pwd = pwd.rstrip('\n\r')
            ssh_client, status = ssh_session_connector(tes_ip, pwd)
            if status:
                print Fore.GREEN + Style.BRIGHT + "Got a valid Password {%s} " % pwd
                ssh_client.close()
                break
            else:
                continue
    if not validated_password:
        raise Exception("Failed to set a valid password")
    return validated_password


init()

try:

    print Style.BRIGHT + "\n################### LOADING CONFIGURATIONS... ###################"
    passwords, password, ranges = load_configuration()
    check_iprange_and_retrieve_available_ips(ranges)

    print Style.BRIGHT + "\n################ FULFILLING PROJECTS REQUIREMENTS ################"

    try:
        for reached_ip in reachable_ips:
            device_data = {}
            password = set_password(reached_ip, passwords, password)
            stdout_data = get_device_information(reached_ip, password)
            device_data["data"] = stdout_data
            devices_data[reached_ip] = device_data
    except Exception as ge:
        print Fore.RED + Style.BRIGHT + "Caught: ", ge
        sys.exit()
    print Fore.WHITE + Style.BRIGHT + json.dumps(devices_data,
                                                 sort_keys=True, indent=4, separators=(',', ': '))
    sys.exit()
except KeyboardInterrupt:
    print Fore.CYAN + Style.BRIGHT + "\nExecution aborted by the user"
    sys.exit()

deinit()
