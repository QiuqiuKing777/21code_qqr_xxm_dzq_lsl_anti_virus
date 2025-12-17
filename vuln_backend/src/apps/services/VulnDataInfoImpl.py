from src.apps.models.VulnDataModel import get_vuln_data_table
from src.extension import *

columns = ['vuln_id', 'vuln_cve_id', 'vuln_cnvd_id', 'cnvd_id', 'cnvd_title', 'cnvd_msg', 'cnvd_creattime', 'cnvd_updatetime',
           'cnvd_reference_link', 'cnvd_publisher', 'cnvd_base_sever', 'cnvd_base_severity', 'cve_id', 'cve_title', 'cve_msg',
           'cve_creattime', 'cve_updatetime', 'cve_reference_link', 'cve_publisher', 'cve_base_sever', 'cve_base_severity']


def getVulnById(the_vuln_id):
    vuln_details_table = get_vuln_data_table()
    session = get_db_connection()
    stmt = select(
        vuln_details_table.c.vuln_id,
        vuln_details_table.c.vuln_cve_id,
        vuln_details_table.c.vuln_cnvd_id,
        vuln_details_table.c.cnvd_id,
        vuln_details_table.c.cnvd_title,
        vuln_details_table.c.cnvd_msg,
        vuln_details_table.c.cnvd_creattime,
        vuln_details_table.c.cnvd_updatetime,
        vuln_details_table.c.cnvd_reference_link,
        vuln_details_table.c.cnvd_publisher,
        vuln_details_table.c.cnvd_base_sever,
        vuln_details_table.c.cnvd_base_severity,
        vuln_details_table.c.cve_id,
        vuln_details_table.c.cve_title,
        vuln_details_table.c.cve_msg,
        vuln_details_table.c.cve_creattime,
        vuln_details_table.c.cve_updatetime,
        vuln_details_table.c.cve_reference_link,
        vuln_details_table.c.cve_publisher,
        vuln_details_table.c.cve_base_sever,
        vuln_details_table.c.cve_base_severity
    ).where(vuln_details_table.c.vuln_id == the_vuln_id)
    result = session.execute(stmt).fetchall()
    result_dicts = [dict(zip(columns, row)) for row in result]
    session.close()
    return jsonify(result_dicts)

