from src.apps.models.UsedDataModel import get_used_data_table
from src.extension import *

columns=['product_id','company_id']

def getUsedById(the_product_id,the_company_id):
    used_data_table = get_used_data_table()
    session = get_db_connection()
    stmt=select(used_data_table.c.product_id,
                used_data_table.c.company_id,
                ).where(used_data_table.c.product_id == the_product_id and used_data_table.c.company_id==the_company_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    #print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def insUsed(attr_dict):
    used_data_table = get_used_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = used_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200

def delUsed(company_id,product_id):
    used_data_table = get_used_data_table()
    session = get_db_connection()

    try:
        # 检查记录是否存在
        exists_query = exists().where(used_data_table.c.company_id == company_id and used_data_table.c.product_id == product_id)
        record_exists = session.query(exists_query).scalar()

        if record_exists:
            # 如果记录存在，执行删除操作
            del_used_statement = used_data_table.delete().where(used_data_table.c.company_id == company_id and used_data_table.c.product_id == product_id)
            session.execute(del_used_statement)
            session.commit()
            return jsonify({"message": "数据删除成功"}), 200
        else:
            # 如果记录不存在，返回失败消息
            return jsonify({"message": "数据删除失败！数据不存在！"}), 404
    except Exception as e:
        # 如果发生异常，回滚事务并返回错误消息
        session.rollback()
        return jsonify({"message": "数据删除失败，服务器内部错误"}), 500
    finally:
        # 确保 session 被关闭
        session.close()