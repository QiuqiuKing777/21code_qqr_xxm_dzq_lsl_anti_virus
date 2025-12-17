from src.apps.models.AtkMsgDataModel import get_atk_msg_data_table
from src.extension import *

columns=['msg_id','vuln_id','product_id','company_id']

def getAtkMsgById(atk_msg_id):
    atk_msg_data_table = get_atk_msg_data_table()
    session = get_db_connection()
    stmt=select(atk_msg_data_table.c.msg_id,
                atk_msg_data_table.c.vuln_id,
                atk_msg_data_table.c.product_id,
                atk_msg_data_table.c.company_id
                ).where(atk_msg_data_table.c.msg_id == atk_msg_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    #print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def delMsg(atk_msg_id):
    msg_data_table = get_atk_msg_data_table()
    session = get_db_connection()

    try:
        exists_query = exists().where(msg_data_table.c.msg_id == atk_msg_id)
        record_exists = session.query(exists_query).scalar()

        if record_exists:

            del_msg_statement = msg_data_table.delete().where(msg_data_table.c.msg_id == atk_msg_id)

            session.execute(del_msg_statement)

            session.commit()
            return jsonify({"message": "数据删除成功"}), 200
        else:
            return jsonify({"message": "数据删除失败！数据不存在！"}), 404
    except Exception as e:

        session.rollback()
        return jsonify({"message": "数据删除失败，服务器内部错误"}), 500
    finally:
        session.close()

def insAtkMsg(attr_dict):
    msg_data_table = get_atk_msg_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = msg_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200