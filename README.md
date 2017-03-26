# snmp-basics

Steps to get started.

1. Make sure to have the SNMP Agent running on the virtual mote setup using Contiki. For step by step instructions refer: https://github.com/ca7erina/contiki-snmp

2. Project requires Maven. Ensure it's present on your machine. 

3. Run IoTManager.java (this will run with SNMPv1)  with args as ip:port. This should be [aaaa::206:98ff:fe00:232]/1610 

4. Run IoTManagerSNMPv3.java (this will run SNMPv3) with args as in last step.
