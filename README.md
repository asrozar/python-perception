Perception
==========

Perception is a tool used to gain better network visibility by pulling LAN information from IOS
network devices. Inventory information is indexed using Splunk.


First thing to do is edit the app/config/configuration.yml file. Either store it in `/etc/perception/configuration.yml`
or set the `PERCEPTION_CONFIG` env variable.

Example Configuration

    # Database Info
    drivername: postgres
    host: localhost
    database: perception_db
    username: perception_user
    password: perception_passwd

    # Application Info
    discovery_mode: passive

    # You should not use this
    # Setup PKI and stop being lazy!
    # Svc Account password
    # svc_account_passwd: insecure_password

    # Splunk Indexer Info
    splunk_indexer: True
    splunk_host: host
    splunk_username: username
    splunk_password: super_secure_password
    splunk_api_port: 8089
    splunk_index: perception_index`

PostgreSQL 8.4 and ^ is supported.

Next install requirements:

`pip install -r requirements`

Then run the migration:

`alembic upgrade head`


There are two parts to this application.

1) Perception CLI

    The cli is used to configure the Perception application (ie. add core routers/switches) and should
    be intuitive for network admins that are familiar with IOS type cli's. There is also show commands
    to see current infrastructure and locally connected hosts.
    
        # ./perception.py

2) Perception Daemon
    
        # sudo ./perceptiond.py start | stop | restart

    The Daemon manages three process. The SeedStarter(), DiscoveryProtocolSpider(), and RSInventoryUpdater().
    It is required that the service accounts used for for Perception are configured to use
    `SSH public key authentication`. You can find configuration examples here:[NSRC_ORG](https://nsrc.org/workshops/2016/apricot2016/raw-attachment/wiki/Track5Wireless/cisco-ssh-auth.htm)
    and here: [Cisco Support Forum](https://supportforums.cisco.com/document/110946/ssh-using-public-key-authentication-ios-and-big-outputs).
    
    `SeedStarter()` checks for new seed routers To interrogate.
    
    The following example show how to add a seed router in the Perception CLI:
    
    `hostname> config`
    
    `hostname(config)# seeds`
    
    `hostname(config/seeds)# add 10.1.1.1 info_svc_account`.
    
    The interrogation of the network devices yields information about locally connected hosts, subnets
    arp-cache tables and discovery protocol information. If discovery mode is configured as "active" [default=passive], during 
    interrogation the local hosts will be port scanned using `nmap -sS -sV host_ip`.
    
    `DiscoveryProtocolSpider()` checks the DiscoveryProtocolFinding table for new network devices to
    interrogate and adds them to the SeedRouter table.
    
    `RSInventoryUpdater()` is the process to re-interrogate the network devices and keep the inventory up
    to date.
    
    Show commands:
    
    `show infrastructure` Displays the discovered network devices.
    
    `show seeds` Displays the current devices.
