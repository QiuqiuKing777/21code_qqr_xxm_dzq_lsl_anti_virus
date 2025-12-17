from src.apps.models.AtkMsgDataModel import get_atk_msg_data_table
from src.apps.models.CompanyDataAModel import get_company_data_table
from src.apps.models.UsedDataModel import get_used_data_table
from src.extension import *

columns=['company_id','company_name','finance_scale']

bd_view="""CREATE VIEW vuln_details AS SELECT v.vuln_id,v.vuln_cnvd_id,v.vuln_cve_id,cnvd.cnvd_id,cnvd.cnvd_title,cnvd.cnvd_msg,cnvd.cnvd_creattime,cnvd.cnvd_updatetime,cnvd.cnvd_reference_link,cnvd.cnvd_publisher,cnvd.cnvd_base_sever,cnvd.cnvd_base_severity,cve.cve_id,cve.cve_title,cve.cve_msg,cve.cve_creattime,cve.cve_updatetime,cve.cve_reference_link,cve.cve_publisher,cve.cve_base_sever,cve.cve_base_severity FROM vuln v LEFT JOIN cnvd_vuln cnvd ON v.vuln_cnvd_id = cnvd.cnvd_id LEFT JOIN cve_vuln cve ON v.vuln_cve_id = cve.cve_id"""

def getCompanyById(the_company_id):
    company_data_table = get_company_data_table()
    session = get_db_connection()

    stmt=select(company_data_table.c.company_id,
                company_data_table.c.company_name,
                company_data_table.c.finance_scale,
                ).where(company_data_table.c.company_id == the_company_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    #print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def insCompany(attr_dict):
    print(attr_dict)
    company_data_table = get_company_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = company_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200

def delCompany(company_id):
    company_data_table = get_company_data_table()
    session = get_db_connection()
    used_data_table = get_used_data_table()
    msg_data_table=get_atk_msg_data_table()
    engine = session.bind
    with engine.connect() as conn:
        conn.execute("DROP VIEW IF EXISTS vuln_details")
    session.commit()
    session.close()
    session = get_db_connection()
    try:
        # 检查记录是否存在
        exists_query = exists().where(company_data_table.c.company_id == company_id)
        record_exists = session.query(exists_query).scalar()
        if record_exists:
            # 如果记录存在，执行删除操作
            del_company_statement = company_data_table.delete().where(company_data_table.c.company_id == company_id)
            del_used_statement = used_data_table.delete().where(used_data_table.c.company_id == company_id)
            del_msg_statement = msg_data_table.delete().where(msg_data_table.c.company_id == company_id)

            session.execute(del_company_statement)
            session.execute(del_used_statement)
            session.execute(del_msg_statement)
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

    session = get_db_connection()
    engine = session.bind
    with engine.connect() as conn:
        conn.execute(bd_view)
    session.commit()
    session.close()

