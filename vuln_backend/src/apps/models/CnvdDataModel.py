from src.extension import *

metadata = MetaData()

def get_cnvd_vuln_data_table():
    return Table('cnvd_vuln', metadata, autoload_with=db.engine)