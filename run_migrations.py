#!/usr/bin/python2
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine
from sqlalchemy.sql import text
import sys


def main():

    perceptiondb_user_password = sys.argv[1]
    engine = create_engine('postgresql://postgres@localhost/perceptiondb')

    conn = engine.connect()
    create_perceptiondb_user = text("CREATE USER perceptiondb_user WITH password '%s';" % perceptiondb_user_password)
    alter_perceptiondb = text("ALTER DATABASE perceptiondb OWNER TO perceptiondb_user;")

    conn.execute(create_perceptiondb_user)
    conn.execute(alter_perceptiondb)
    conn.close()

    alembic_cfg = Config("/usr/local/lib/python2.7/dist-packages/perception/database/alembic.ini")
    command.upgrade(alembic_cfg, "head")


if __name__ == "__main__":
    main()
