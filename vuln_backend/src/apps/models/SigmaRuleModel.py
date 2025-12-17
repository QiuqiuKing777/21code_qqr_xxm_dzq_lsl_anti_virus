from src.extension import *

metadata = MetaData()

def get_sigma_rule_table():
    return Table('sigma_rule', metadata, autoload_with=db.engine)