from src.apps.models.AffectDataModel import get_affect_data_table
from src.extension import *

columns=['vuln_id','product_id']

def getAffectById(the_vuln_id,the_product_id):
    affect_data_table = get_affect_data_table()
    session = get_db_connection()
    stmt=select(affect_data_table.c.vuln_id,
                affect_data_table.c.product_id,
                ).where(affect_data_table.c.product_id == the_product_id and affect_data_table.c.vuln_id==the_vuln_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    #print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def insaffect(attr_dict):
    affect_data_table = get_affect_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = affect_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200