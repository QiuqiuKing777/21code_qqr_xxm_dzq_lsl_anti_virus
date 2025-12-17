from src.extension import *

metadata = MetaData()

def get_product_data_table():
    return Table('product', metadata, autoload_with=db.engine)