from src.extension import *

metadata = MetaData()

def get_vuln_data_table():
    return Table('vuln_details', metadata, autoload_with=db.engine)