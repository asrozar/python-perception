Perception
==========

Perception is a tool used to gain better network visibility by pulling LAN information from IOS
network devices.


First thing to do is edit the app/config/database.yml file.

Add host, database, user, and password.

PostgreSQL 8.4 and ^ is supported.

This tool is still under development and has not been fully released. There are two parts to this
tool.

1) Perception CLI

    The cli is used to configure the Perception application (ie. add core routers/switches) and should
    be intuitive for network admins that are familiar with IOS type cli's. There is also show commands
    to see current infrastructure and locally connected hosts.
    
        # ./perception.py

2) Perception Daemon
    
        # sudo ./perceptiond.py start | stop | restart

    The Daemon manages three process. The SeedStarter(), DiscoveryProtocolSpider(), and RSInventorySpider().
    It is required that the service accounts used for for Perception are configured to use
    `SSH public key authentication`. You can find configuration examples here:[NSRC_ORG](https://nsrc.org/workshops/2016/apricot2016/raw-attachment/wiki/Track5Wireless/cisco-ssh-auth.htm)
    and here: [Cisco Support Forum](https://supportforums.cisco.com/document/110946/ssh-using-public-key-authentication-ios-and-big-outputs).
    
    `SeedStarter()` checks for new seed routers To interrogate.
    
    The following example show how to add a seed router in the Perception CLI:
    
    `hostname: config`
    
    `hostname(config): seeds`
    
    `hostname(config/seeds): add 10.1.1.1 info_svc_account`.
    
    The interrogation of the network devices yields information about locally connected hosts, subnets
    arp-cache tables and discovery protocol information. During interrogation the local hosts are port scanned
    using `nmap -sS -sV host_ip`.
    
    `DiscoveryProtocolSpider()` checks the DiscoveryProtocolFinding table for new network devices to
    interrogate and adds them to the SeedRouter table.
    
    `RSInventorySpider()` is the process to re-interrogate the network devices and keep the inventory up
    to date.
    
    Show commands:
    
    `show infrastructure` Displays the discovered network devices.
    
    `show seeds` Displays the current devices.
    
================================================================================================