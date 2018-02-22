"""

1)Before you run the code you have to enter the following commands to each router in a network: 

#snmp-server community public RO

Also please make sure that one of the routing protocol has been implemented beforehead

2) Please install PySNMP package


The task is to know an interface description and interface status for each interface. In oder to collect information, we are going to use SNMP and based on OIDs we can retrieve any information we want to. 

********************************************************************

"""


        def snmpget(oid):
 
  from pysnmp.entity.rfc3413.oneliner import cmdgen
  
  #enter IP address
 
  IP_HOST = raw_input("Please type an IP address: ")
  port number = 161
  SNMP_COMMUNITY
 
  cmdGen = cmdgen.CommandGenerator()
 
  errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.CommunityData(SNMP_COMMUNITY),
    cmdgen.UdpTransportTarget((IP_HOST, port_number)),
    oid
  )
 
  # Error correction 
  if errorIndication:
    print(errorIndication)
  else:
    if errorStatus:
      print('%s at %s' % (
        errorStatus.prettyPrint(),
        errorIndex and varBinds[int(errorIndex)-1] or '?'
       )
     )
    else:
      for name, val in varBinds:
        #print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        return val

#print the result
print( 'Interface ' + snmpget('1.3.6.1.2.1.2.1') ) # interface info
print( 'List: ' + snmpget('1.3.6.1.2.1.2.2') ) # a list of interface entries
