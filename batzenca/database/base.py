import datetime

import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class EntryNotFound(ValueError):
    pass
