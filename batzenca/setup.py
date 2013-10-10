from database.base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import BATZENCADIR

import os

if not os.path.exists(BATZENCADIR):
    os.mkdir(BATZENCADIR)
    os.chmod(BATZENCADIR, 0700)

if not os.path.isdir(BATZENCADIR):
    raise IOError("Cannot create configuration directory '%' because a file with the same name exists already."%BATZENCADIR)

engine = create_engine('sqlite:///%s/batzenca.db'%BATZENCADIR, echo=False)

Base.metadata.create_all(engine)

session =  sessionmaker(bind=engine)()
session.commit()
