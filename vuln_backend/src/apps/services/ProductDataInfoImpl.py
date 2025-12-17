from src.apps.models.ProductDataModel import get_product_data_table
from src.extension import *

columns=['product_id','product_name','product_version']

def getProductById(the_product_id):
    product_data_table = get_product_data_table()
    session=get_db_connection()
    stmt=select(product_data_table.c.product_id,
                product_data_table.c.product_name,
                product_data_table.c.product_version,
                ).where(product_data_table.c.product_id == the_product_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    #print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def insProduct(attr_dict):
    product_data_table = get_product_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = product_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200

