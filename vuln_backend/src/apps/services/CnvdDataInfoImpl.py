import pymysql

from src.apps.models.CnvdDataModel import get_cnvd_vuln_data_table
from src.extension import *
from src.apps.models.VulnDataModel import get_vuln_data_table
import json

columns = ['cnvd_id', 'cnvd_title', 'cnvd_msg', 'cnvd_creattime',
               'cnvd_updatetime', 'cnvd_reference_link', 'cnvd_publisher',
               'cnvd_base_sever', 'cnvd_base_severity']

def getVulnByCnvdId(vuln_id):
    cnvd_vuln_data_table = get_cnvd_vuln_data_table()
    session=get_db_connection()
    stmt=select(cnvd_vuln_data_table.c.cnvd_id,
                cnvd_vuln_data_table.c.cnvd_title,
                cnvd_vuln_data_table.c.cnvd_msg,
                cnvd_vuln_data_table.c.cnvd_creattime,
                cnvd_vuln_data_table.c.cnvd_updatetime,
                cnvd_vuln_data_table.c.cnvd_reference_link,
                cnvd_vuln_data_table.c.cnvd_publisher,
                cnvd_vuln_data_table.c.cnvd_base_sever,
                cnvd_vuln_data_table.c.cnvd_base_severity
                ).where(cnvd_vuln_data_table.c.cnvd_id == vuln_id)
    result=session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    print(result_dicts)
    session.close()
    return jsonify(result_dicts)

def insVulnCnvd(attr_dict):
    cnvd_vuln_data_table = get_cnvd_vuln_data_table()
    session = get_db_connection()

    # ins,mark it dict could be a parameter of func value
    insert_stmt = cnvd_vuln_data_table.insert().values(attr_dict)
    session.execute(insert_stmt)
    session.commit()
    session.close()

    return jsonify({"message": "数据插入成功"}), 200

def delVulnCnvd(vuln_id):
    db = pymysql.connect(host="localhost", user="root", password="15211759819Zd", database="nvd_database")
    cursor = db.cursor()

    try:
        exestring_cnvd = f"DELETE from cnvd_vuln where cnvd_id='{vuln_id}';"
        exestring_vuln = f"DELETE from vuln where vuln_cnvd_id='{vuln_id}';"
        if vuln_id=='cnvd_1':
            raise Exception()
        result = cursor.execute(exestring_vuln)
        db.commit()
        result = cursor.execute(exestring_cnvd)
        db.commit()
        return jsonify({"message": "数据删除成功"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"message": "数据删除失败"}), 404
    finally:
        db.close()


def updateVulnCnvd(id, data):
    db = pymysql.connect(host="localhost", user="root", password="15211759819Zd", database="nvd_database")
    cursor=db.cursor()

    try:
        json_data = json.dumps(data)
        json_data = json_data.replace("'", '"')
        exestring=f"CALL update_cnvd_vuln('{id}', '{json_data}');"

        print(exestring)
        result = cursor.execute(exestring)
        db.commit()
        return jsonify({"message": "数据更新成功"}), 200
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()





