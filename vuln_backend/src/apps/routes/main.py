import json
from flask import Blueprint, jsonify, request,Response

from src.apps.services.CnvdDataInfoImpl import getVulnByCnvdId,delVulnCnvd,insVulnCnvd,updateVulnCnvd
from src.apps.services.CveDataInfoImpl import getVulnByCveId,delVulnCve,insVulnCve,updateVulnCve
from src.apps.services.VulnDataInfoImpl import getVulnById
from src.apps.services.ProductDataInfoImpl import getProductById,insProduct
from src.apps.services.CompanyDataInfoImpl import getCompanyById,insCompany,delCompany
from src.apps.services.AffectDataInfoImpl import  getAffectById,insaffect
from src.apps.services.AtkMsgDataInfoImpl import  getAtkMsgById,delMsg,insAtkMsg
from src.apps.services.UsedDataInfoImpl import  getUsedById,delUsed,insUsed
from src.apps.services.MalYaraUpload import MalYaraUpload
from src.apps.services.MalSigmaUpload import MalSigmaUpload
from src.apps.services.MalSigmaScan import MalSigmaScan
from src.apps.services.MalYaraScan import MalYaraScan

main = Blueprint('main', __name__)

@main.route('/', methods=['GET'])
def index():
    return jsonify({"message": "Welcome to the API"})

#yara upload
@main.route("/uploadYaraRule", methods=["POST"])
def upload_yara_rule():
    try:
        f = request.files.get("file")
        source_name = request.form.get("source_name", "manual-upload")
        data = MalYaraUpload.upload_single(f, source_name)
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "code": "BAD_REQUEST", "message": str(e)}), 400

@main.route("/uploadYaraRuleZip", methods=["POST"])
def upload_yara_rule_zip():
    try:
        f = request.files.get("file")
        source_name = request.form.get("source_name", "manual-upload")
        data = MalYaraUpload.upload_zip(f, source_name)
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "code": "BAD_REQUEST", "message": str(e)}), 400

#sigma upload
@main.route("/uploadSigmaRuleYaml", methods=["POST"])
def upload_sigma_json():
    try:
        f = request.files.get("file")
        source_name = request.form.get("source_name", "manual-upload")
        data = MalSigmaUpload.upload_single_json(f, source_name)
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "code": "BAD_REQUEST", "message": str(e)}), 400

@main.route("/uploadSigmaRuleZip", methods=["POST"])
def upload_sigma_zip():
    try:
        f = request.files.get("file")
        source_name = request.form.get("source_name", "manual-upload")
        data = MalSigmaUpload.upload_zip(f, source_name)
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "code": "BAD_REQUEST", "message": str(e)}), 400

#sigma scan
@main.route("/detectEvtxWithSigma", methods=["POST"])
def detect_evtx_with_sigma():
    try:
        f = request.files.get("file")
        label = request.form.get("label", "")
        rule_set = request.form.get("rule_set", "enabled")
        return_level = request.form.get("return_level", "summary")

        data = MalSigmaScan.detect_evtx_with_sigma(
            f,
            label=label,
            rule_set=rule_set,
            return_level=return_level
        )
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "code": "BAD_REQUEST", "message": str(e)}), 400

#yara scan
@main.route("/scanSampleWithYara", methods=["POST"])
def scan_sample_with_yara():
    try:
        f = request.files.get("file")
        label = request.form.get("label", "")
        rule_set = request.form.get("rule_set", "enabled")

        data = MalYaraScan.scan_sample_with_yara(
            f,
            label=label,
            rule_set=rule_set
        )
        return jsonify(data)
    except Exception as e:
        msg = str(e)
        code = "BAD_REQUEST"
        http = 400
        if msg == "FILE_TOO_LARGE":
            code = "FILE_TOO_LARGE"
        elif msg == "SCAN_TIMEOUT":
            code = "SCAN_TIMEOUT"
        return jsonify({"ok": False, "code": code, "message": msg}), http


#cnvd
@main.route('/CnvdVulnById/<cnvd_id>', methods=['GET','POST'])
def cnvd_vuln(cnvd_id):
    res= getVulnByCnvdId(cnvd_id)
    return res

@main.route('/delCnvdVulnById/<cnvd_id>', methods=['GET','POST'])
def delCnvdVulnById(cnvd_id):
    res= delVulnCnvd(cnvd_id)
    return res

@main.route('/insertCnvdVuln', methods=['POST'])
def insertCnvdVuln():
    data = request.get_json()
    print(data)
    try:
        res = insVulnCnvd(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500

@main.route('/updateCnvdVuln/<string:id>', methods=['PUT'])
def update_cnvd_vuln(id):
    data = request.get_json()
    try:
        res = updateVulnCnvd(id,data)
        return jsonify({"message": "更新成功"}), 200
    except Exception as e:
        return jsonify({"message": f"更新失败: {str(e)}"}), 500

#cve
@main.route('/CveVulnById/<cve_id>', methods=['GET','POST'])
def cve_vuln(cve_id):
    res= getVulnByCveId(cve_id)
    return res

@main.route('/delCveVulnById/<cve_id>', methods=['GET','POST'])
def delCveVulnById(cve_id):
    res= delVulnCve(cve_id)
    return res

@main.route('/insertCveVuln', methods=['POST'])
def insertCveVuln():
    data = request.get_json()
    try:
        res = insVulnCve(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500

@main.route('/updateCveVuln/<string:id>', methods=['PUT'])
def update_cve_vuln(id):
    data = request.get_json()
    #print(data)
    try:
        res = updateVulnCve(id,data)
        return jsonify({"message": "更新成功"}), 200
    except Exception as e:
        return jsonify({"message": f"更新失败: {str(e)}"}), 500

#vuln
@main.route('/VulnById/<vuln_id>', methods=['GET','POST'])
def vuln_by_id(vuln_id):
    res= getVulnById(vuln_id)
    return res

#product
@main.route('/ProductById/<product_id>', methods=['GET','POST'])
def product_by_id(product_id):
    res= getProductById(product_id)
    return res

@main.route('/insertProduct', methods=['POST'])
def insertProduct():
    data = request.get_json()
    print(data)
    try:
        res = insProduct(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500

#company
@main.route('/CompanyById/<company_id>', methods=['GET','POST'])
def company_by_id(company_id):
    res= getCompanyById(company_id)
    return res

@main.route('/insertCompany', methods=['GET','POST'])
def insertCompany():
    data = request.get_json()
    print(data)
    try:
        res = insCompany(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500

@main.route('/delCompany/<company_id>', methods=['GET','POST'])
def deleteCompany(company_id):
    res= delCompany(company_id)
    return res

#affect
@main.route('/Affects/<vuln_id>/<product_id>', methods=['GET','POST'])
def affects(vuln_id, product_id):
    res= getAffectById(vuln_id, product_id)
    return res

@main.route('/insertAffect', methods=['GET','POST'])
def insertAffect():
    data = request.get_json()
    print(data)
    try:
        res = insaffect(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500

#atk_msg
@main.route('/AtkMsgById/<atk_msg_id>', methods=['GET','POST'])
def atk_msg_by_id(atk_msg_id):
    res=getAtkMsgById(atk_msg_id)
    return res

@main.route('/delMsgById/<atk_msg_id>', methods=['GET','POST'])
def delMsgById(atk_msg_id):
    res= delMsg(atk_msg_id)
    return res

@main.route('/insertMsg', methods=['POST'])
def insertMsg():
    data = request.get_json()
    print(data)
    try:
        res = insAtkMsg(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500

#used
@main.route('/UsedById/<product_id>/<company_id>', methods=['GET','POST'])
def used_by_id(product_id,company_id):
    res= getUsedById(product_id,company_id)
    return res

@main.route('/delUsedById/<company_id>/<product_id>', methods=['GET','POST'])
def delUsedById(company_id,product_id):
    res=delUsed(company_id,product_id)
    return res

@main.route('/insertUsed', methods=['POST'])
def insertUsed():
    data = request.get_json()
    print(data)
    try:
        res = insUsed(data)
        return jsonify({"message": "插入成功"}), 200
    except Exception as e:
        return jsonify({"message": f"插入失败: {str(e)}"}), 500