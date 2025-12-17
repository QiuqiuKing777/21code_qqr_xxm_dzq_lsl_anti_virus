# from sqlalchemy import event
# from sqlalchemy import text
#
# def create_triggers(engine):
#     connection = engine.connect()
#
#     trigger_sql=text("DELIMITER //DROP TRIGGER IF EXISTS after_cnvd_ins_trigger;CREATE TRIGGER after_cnvd_ins_triggerAFTER INSERT ON cnvd_vulnFOR EACH ROWBEGININSERT INTO vuln (vuln_cve_id, vuln_cnvd_id)VALUES (NULL, NEW.cnvd_id);END;//DELIMITER ;")
#     connection.execute(trigger_sql)
#     trigger_sql=text("DELIMITER //DROP TRIGGER IF EXISTS after_cve_ins_trigger;CREATE TRIGGER after_cve_ins_triggerAFTER INSERT ON cve_vulnFOR EACH ROWBEGININSERT INTO vuln (vuln_cve_id, vuln_cnvd_id)VALUES (NEW.cve_id,NULL);END;//DELIMITER ;")
#     connection.execute(trigger_sql)
#
#     connection.close()