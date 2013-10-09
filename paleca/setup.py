from base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import PALECADIR

import os

if not os.path.exists(PALECADIR):
    os.mkdir(PALECADIR)
    os.chmod(PALECADIR, 0700)

if not os.path.isdir(PALECADIR):
    raise IOError("Cannot create configuration directory '%' because a file with the same name exists already."%PALECADIR)

engine = create_engine('sqlite:///%s/paleca.db'%PALECADIR, echo=False)

Base.metadata.create_all(engine)

session =  sessionmaker(bind=engine)()
session.commit()
