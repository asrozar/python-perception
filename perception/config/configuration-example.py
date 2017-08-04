# ------------------
# Configuration File
# ------------------

# --------------
# Time Zone Info
# --------------

timezone = 'US/Eastern'

# -------------
# Database Info
# -------------
db_drivername = 'postgres'
db_host = 'localhost'
database = 'perceptiondb'
db_username = 'perceptiondb_user'
db_password = 'perceptiondb_user_password'

# ----------------
# Application Info
# ----------------
discovery_mode = 'passive'

# -------------------------------------
# You should not uncomment and use this
# Just setup PKI and stop being lazy
# Svc Account password
# -------------------------------------
# svc_account_passwd = 'should_setup_pki'

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
es_index = 'perception'
es_direct = True

# -------------------
# Splunk Indexer Info
# -------------------
splunk_indexer = False
splunk_host = 'splunk.host.local'
splunk_username = 'splunk_user'
splunk_password = 'should_setup_pki'
splunk_api_port = 8089
splink_index = 'perception'

