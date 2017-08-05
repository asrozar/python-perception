from perception.shared.variables import db_config
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import sessionmaker


class Sql(object):
    def __init__(self):
        self.create_session()

    @staticmethod
    def create_session():

        engine = create_engine(URL(**db_config), pool_size=20)
        Session = sessionmaker(bind=engine)
        db_session = Session()
        return db_session

    @staticmethod
    def get_or_create(session, model, **kwargs):
        instance = session.query(model).filter_by(**kwargs).first()
        if instance:
            return instance
        else:
            instance = model(**kwargs)
            session.add(instance)
            session.commit()
            return instance
