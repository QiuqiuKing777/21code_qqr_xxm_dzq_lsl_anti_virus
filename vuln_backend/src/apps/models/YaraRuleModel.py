from src.extension import *

metadata = MetaData()

def get_yara_rule_table():
    return Table('yara_rule', metadata, autoload_with=db.engine)

def get_yara_uncompiled_table():
    return Table("yara_uncompiled", metadata, autoload_with=db.engine)