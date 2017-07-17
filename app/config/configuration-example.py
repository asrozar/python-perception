# ------------------
# Configuration File
# ------------------

# -------------
# Database Info
# -------------
db_drivername = 'postgres'
db_host = 'localhost'
database = 'perceptiondb'
db_username = 'perception'
db_password = 'perception_password'

# ----------------
# Application Info
# ----------------
discovery_mode = 'passive'

# -------------------------------------
# You should not uncomment and use this
# Just setup PKI and stop being lazy
# Svc Account password
# -------------------------------------
svc_account_passwd = 'should_setup_pki'

# -------------------
# Splunk Indexer Info
# -------------------
splunk_indexer = True
splunk_host = 'splunk.host.local'
splunk_username = 'splunk_user'
splunk_password = 'should_setup_pki'
splunk_api_port = 8089

# -------------------------
# Nessus hosts and API keys
# -------------------------
nessus_hosts = [

    ('nessus.host1.net',
     'nessus_access_key',
     'nessus_secret_key'),

    ('nessus.host2.net',
     'nessus_access_key',
     'nessus_secret_key')
]

# -------------------------
# How often to check Nessus
# -------------------------
sleep_hours = 12
