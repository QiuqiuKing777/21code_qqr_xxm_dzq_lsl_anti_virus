from src.extension import *

metadata = MetaData()

def get_affect_data_table():
    return Table('affects', metadata, autoload_with=db.engine)
