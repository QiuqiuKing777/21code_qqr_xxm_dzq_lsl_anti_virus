from src.apps.models.CveDataModel import get_cve_vuln_data_table
from src.extension import *
from src.apps.models.VulnDataModel import get_vuln_data_table

columns = ['cve_id', 'cve_title', 'cve_msg', 'cve_creattime',
               'cve_updatetime', 'cve_reference_link', 'cve_publisher',
               'cve_base_sever', 'cve_base_severity']

def getVulnByCveId(cve_id):
    cve_vuln_data_table = get_cve_vuln_data_table()
    session=get_db_connection()
    stmt=select(cve_vuln_data_table.c.cve_id,
                cve_vuln_data_table.c.cve_title,
                cve_vuln_data_table.c.cve_msg,
                cve_vuln_data_table.c.cve_creattime,
                cve_vuln_data_table.c.cve_updatetime,
                cve_vuln_data_table.c.cve_reference_link,
                cve_vuln_data_table.c.cve_publisher,
                cve_vuln_data_table.c.cve_base_sever,
                cve_vuln_data_table.c.cve_base_severity
                ).where(cve_vuln_data_table.c.cve_id == cve_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    #print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def insVulnCve(attr_dict):
    cve_vuln_data_table = get_cve_vuln_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = cve_vuln_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200

def delVulnCve(vuln_id):
    cve_vuln_data_table = get_cve_vuln_data_table()
    session = get_db_connection()
    vuln_data_table = get_vuln_data_table()
    try:
        # 检查记录是否存在
        exists_query = exists().where(cve_vuln_data_table.c.cve_id == vuln_id)
        record_exists = session.query(exists_query).scalar()

        if record_exists:
            # 如果记录存在，执行删除操作
            del_cve_statement = cve_vuln_data_table.delete().where(cve_vuln_data_table.c.cve_id == vuln_id)
            del_vuln_statement = vuln_data_table.delete().where(vuln_data_table.c.vuln_cve_id == vuln_id)
            session.execute(del_cve_statement)
            session.execute(del_vuln_statement)
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


def updateVulnCve(id, data):
    cve_vuln_data_table = get_cve_vuln_data_table()
    session = get_db_connection()
    print(id, data)

    try:
        # 获取所有字段名
        valid_fields = [column.name for column in cve_vuln_data_table.columns]

        # 检查 data 中的键是否有效
        for key in data.keys():
            if key not in valid_fields:
                raise ValueError(f"字段 {key} 不是有效的字段名")

        # 构造更新语句
        update_stmt = (
            cve_vuln_data_table.update()
            .where(cve_vuln_data_table.c.cve_id == id)
            .values(data)
        )

        # 执行更新操作
        result = session.execute(update_stmt)

        # 检查是否有记录被更新
        if result.rowcount == 0:
            raise Exception(f"未找到 CVE ID 为 {id} 的记录")

        # 提交事务
        session.commit()
    except Exception as e:
        # 回滚事务
        print(e)
        session.rollback()
        raise e
    finally:
        # 关闭会话
        session.close()

