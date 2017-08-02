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

# -------------------------
# MessageQueuing
# -------------------------

mq_host = 'mq_host'
mq_port = 5671
mq_ssl = True
mq_user = 'mq_user'
mq_password = 'mq_password'

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
splunk_indexer = True
splunk_host = 'splunk.host.local'
splunk_username = 'splunk_user'
splunk_password = 'should_setup_pki'
splunk_api_port = 8089
splink_index = 'index_name'

