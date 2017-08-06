#!/usr/bin/python2
from alembic.config import Config
from alembic import command
alembic_cfg = Config("/usr/local/lib/python2.7/dist-packages/perception/database/alembic.ini")
command.upgrade(alembic_cfg, "head")
