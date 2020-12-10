import os, json
from base64 import b64encode, b64decode

class LuminaDatabase(object):
    def __init__(self, logger, db_file):
        self.logger = logger
        self.logger.info(f"loading database {os.path.abspath(db_file.name)}")
        self.load(db_file)


    def load(self, db_file):
        self.db_file = db_file
        self.db_file.seek(0, os.SEEK_SET)

        if os.stat(self.db_file.name).st_size == 0:
            # create new db
            self.db = dict()
        else:
            try:
                self.db = json.load(self.db_file)
            except Exception as e:
                self.logger.exception(e)
                self.db_file.close()
                self.db = None
                raise

    def save(self):
        try:
            self.logger.info(f"saving database to {self.db_file.name}")
            self.db_file.seek(0, os.SEEK_SET)
            json.dump(self.db, self.db_file)
        except Exception as e:
            self.logger.exception(e)
            raise
        return True

    def close(self, save=False):
        if save:
            self.save()
        self.db_file.close()
        self.db = None

    def push(self, info):
        """
        return True on new insertion, else False
        """

        # Signature and metadata contains non string data that need to be encoded:
        sig_version = info.signature.version
        signature = b64encode(info.signature.signature).decode("ascii")
        metadata = {
            "func_name"         : info.metadata.func_name,
            "func_size"         : info.metadata.func_size,
            "serialized_data"   : b64encode(info.metadata.serialized_data).decode("ascii"),
        }

        if sig_version != 1:
            self.logger.warning("Signature version {sig_version} not supported. Results might be inconsistent")


        # insert into database
        new_sig = False
        db_entry = self.db.get(signature, None)

        if db_entry is None:
            db_entry = {
                "metadata": list(), # collision/merge not implemented yet. just keep every push queries
                "popularity" : 0
            }
            self.db[signature] = db_entry
            new_sig = True

        db_entry["metadata"].append(metadata)
        db_entry["popularity"] += 1

        return new_sig

    def pull(self,signature):
        """
        return function metadata or None if not found
        """

        sig_version = signature.version
        signature = b64encode(signature.signature).decode("ascii")

        if sig_version != 1:
            self.logger.warning("Signature version {sig_version} not supported. Results might be inconsistent")

        # query database
        db_entry = self.db.get(signature, None)

        if db_entry:
            # take last signature (arbitrary choice)
            metadata = db_entry["metadata"][-1]

            # Decode signature (take that last match for a result)
            metadata = {
                "func_name"         : metadata["func_name"],
                "func_size"         : metadata["func_size"],
                "serialized_data"   : b64decode(metadata["serialized_data"]),
            }

            result = {
                "metadata"   : metadata,
                "popularity" : db_entry["popularity"]
            }

            return result
        return None