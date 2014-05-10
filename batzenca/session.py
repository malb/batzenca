from database.base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import os
import git


class Session:

    _gitignore = """.gitignore
gnupg/pubring.gpg~
gnupg/random_seed
releases
"""

    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            os.mkdir(path)
            os.chmod(path, 0700)

        if not os.path.isdir(path):
            raise IOError("Cannot create configuration directory '%' because a file with the same name exists already."%path)

        if not os.path.exists(self.release_dump_path):
            os.mkdir(self.release_dump_path)
            os.chmod(self.release_dump_path, 0700)

        if not os.path.isdir(self.release_dump_path):
            raise IOError("Cannot create directory '%' because a file with the same name exists already."%self.release_dump_path)
            
        self.db_engine = create_engine('sqlite:///%s/batzenca.db'%path, echo=False)

        Base.metadata.create_all(self.db_engine)

        self.db_session =  sessionmaker(bind=self.db_engine)()
        self.db_session.commit()

        from gnupg import GnuPG
        self.gnupg = GnuPG(path + os.path.sep + "gnupg")

        try:
            git.Repo(self.path)
        except git.InvalidGitRepositoryError:
            repo = git.Repo.init(self.path)
            # git ignore
            open(os.path.join(repo.working_dir, ".gitignore"), "w").write(Session._gitignore)
            # add useful files
            repo.git.add("batzenca.db")
            for filename in ("pubring.gpg", "secring.gpg", "trustdb.gpg"):
                fullpath = os.path.join(repo.working_dir, "gnupg", filename)
                if os.path.exists(fullpath):
                    repo.git.add(fullpath)
            repo.git.commit(m="initial commit")
            
    def commit(self, snapshot=False, *args, **kwds):
        self.db_session.commit()
        if snapshot:
            self.snapshot(*args, **kwds)

    @property
    def query(self):
        return self.db_session.query

    @property
    def add(self):
        return self.db_session.add

    @property
    def add_all(self):
        return self.db_session.add_all

    @property
    def release_dump_path(self):
        """Path for storing releases in .asc and .yaml format."""
        return os.path.join(self.path, "releases")

    def snapshot(self, verbose=False, msg="snapshot"):
        repo = git.Repo(self.path)
        repo.git.add("batzenca.db")
        repo.git.add("gnupg")
        if verbose:
            print repo.git.status()
        if repo.is_dirty():
            out = repo.git.commit(m=msg)
            if verbose:
                print out
        
BATZENCADIR  = os.environ.get("BATZENCADIR", os.path.expanduser("~") + os.path.sep + ".batzenca")
session = Session(BATZENCADIR)

