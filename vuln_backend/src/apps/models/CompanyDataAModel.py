from src.extension import *

metadata = MetaData()

def get_company_data_table():
    return Table('companies', metadata, autoload_with=db.engine)