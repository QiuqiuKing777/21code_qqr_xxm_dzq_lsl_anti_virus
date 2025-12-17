from src.extension import *

metadata = MetaData()

def get_atk_msg_data_table():
    return Table('atk_msg', metadata, autoload_with=db.engine)