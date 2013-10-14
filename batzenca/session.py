from database.base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import os


class Session:
    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            os.mkdir(path)
            os.chmod(path, 0700)

        if not os.path.isdir(path):
            raise IOError("Cannot create configuration directory '%' because a file with the same name exists already."%path)

        self.db_engine = create_engine('sqlite:///%s/batzenca.db'%path, echo=False)

        Base.metadata.create_all(self.db_engine)

        self.db_session =  sessionmaker(bind=self.db_engine)()
        self.db_session.commit()

        from gnupg import GnuPG
        self.gnupg = GnuPG(path + os.path.sep + "gnupg")

    def commit(self):
        self.db_session.commit()

    @property
    def query(self):
        return self.db_session.query
        
BATZENCADIR  = os.environ.get("BATZENCADIR", os.path.expanduser("~") + os.path.sep + ".batzenca")
session = Session(BATZENCADIR)
