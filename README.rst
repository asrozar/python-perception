Perception
==========

Perception is a tool used to gain better network visibility by pulling LAN information from IOS
network devices. Inventory information is indexed using Elasticsearch.

Run the Install::

    ./install.sh

Edit the /etc/perception/config/configuration.py file.

Example Configuration::

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
    # -------------------------

    # MessageQueuing
    # -------------------------
    mq_host = 'localhost'
    mq_port = 5672
    mq_ssl = False
    mq_user = 'guest'
    mq_password = 'guest'

    # --------------------------
    # Elasticsearch Indexer Info
    # --------------------------
    es_host = '127.0.0.1'
    es_port = 9200
    es_ssl = False
    es_index = 'perception'
    es_direct = True

There are two parts to this application.

1) Perception CLI::

    The cli is used to configure the Perception application (ie. add core routers/switches) and should
    be intuitive for network admins that are familiar with IOS type cli's. There is also show commands
    to see current infrastructure and locally connected hosts.
    
    /usr/bin/perception_cli

2) Perception Daemon::

    sudo /usr/bin/perceptiond start | stop | restart

    The Daemon manages three process. The SeedStarter(), DiscoveryProtocolSpider(), and RSInventoryUpdater().
    It is required that the service accounts used for for Perception are configured to use
    SSH public key authentication. You can find configuration examples here:[NSRC_ORG](https://nsrc.org/workshops/2016/apricot2016/raw-attachment/wiki/Track5Wireless/cisco-ssh-auth.htm)
    and here: [Cisco Support Forum](https://supportforums.cisco.com/document/110946/ssh-using-public-key-authentication-ios-and-big-outputs).
    
    SeedStarter() checks for new seed routers To interrogate.
    
    The following example show how to add a seed router in the Perception CLI:
    
    hostname> config
    
    hostname(config)# seeds
    
    hostname(config/seeds)# add 10.1.1.1 info_svc_account
    
    The interrogation of the network devices yields information about locally connected hosts, subnets
    arp-cache tables and discovery protocol information. If discovery mode is configured as "active" [default=passive], during 
    interrogation the local hosts will be port scanned using nmap -sS -sV host_ip.
    
    DiscoveryProtocolSpider() checks the DiscoveryProtocolFinding table for new network devices to
    interrogate and adds them to the SeedRouter table.
    
    RSInventoryUpdater() is the process to re-interrogate the network devices and keep the inventory up
    to date.
    
    Show commands:
    
    show infrastructure Displays the discovered network devices.
    
    show seeds Displays the current devices.
    
    Run commands:
    
    hostname> run discovery on 172.16.1.10
    
    hostname> run discovery on 172.16.1.0/24
    
    hostname> run vuln_scan on 172.16.1.10

    hostname> run vuln_scan on 172.16.1.0/24

