"""
.. module:: base
 
.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>
"""

import datetime

import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class EntryNotFound(ValueError):
    """
    This exception is raised if some query returned an empty result.
    """
    pass
