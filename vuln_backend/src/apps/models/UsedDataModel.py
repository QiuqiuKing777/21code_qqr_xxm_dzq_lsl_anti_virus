from src.extension import *

metadata = MetaData()

def get_used_data_table():
    return Table('used', metadata, autoload_with=db.engine)
