from src.extension import *

metadata = MetaData()

def get_cve_vuln_data_table():
    return Table('cve_vuln', metadata, autoload_with=db.engine)