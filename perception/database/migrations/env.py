from __future__ import with_statement
from alembic import context
from sqlalchemy import engine_from_config, pool, create_engine
from sqlalchemy.engine.url import URL
from logging.config import fileConfig

from os import getenv
import re

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = None

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... config.

# database yaml file for connectivity info
db_yml = getenv('PERCEPTION_DB_INFO')

if db_yml is None:
    db_yml = 'perception/config/database.yml'

new_list = []
reg_clean = re.compile(r'[:]')

with open(db_yml, 'r') as f:
  new_list += [re.sub(r':\s', ':', line.strip()) for line in f if reg_clean.search(line)]
  config_info = dict(map(str, x.split(':')) for x in new_list)

db_info = {'drivername': config_info['drivername'],
           'username': config_info['username'],
           'password': config_info['password'],
           'host': config_info['host'],
           'database': config_info['database']}

# build URL
sqlalchemy_url = '%s://%s:%s@%s/%s' % (config_info['drivername'],
                                       config_info['username'],
                                       config_info['password'],
                                       config_info['host'],
                                       config_info['database'])


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option(sqlalchemy_url)
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = create_engine(URL(**db_info), pool_size=20)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
