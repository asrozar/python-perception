from os import getenv
from perception.config import configuration as config

# ----------------
# environment vars
# ----------------
home_dir = getenv('HOME')
tmp_dir = '/tmp/perception/'
rsinfrastructure_tmp_dir = '%srsinfrastructure/' % tmp_dir
nmap_tmp_dir = '%snmap/' % tmp_dir
db_config = {'drivername': config.db_drivername,
             'host': config.db_host,
             'database': config.database,
             'username': config.db_username,
             'password': config.db_password}