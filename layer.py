import os
import sys
import shlex
import subprocess

from flask import Flask, render_template, request

#init = "terraform init"
#init_shlex = shlex.split(init)
#init_process = subprocess.Popen(init_shlex)

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

# Vulnerability Detection, Reporting and Remediation

@app.route("/vuldescript")
def vuldescript():
    return render_template("vulnerabilitydesc.html")

@app.route("/vulform")
def vulform():
    return render_template("vulnerabilityform.html")

@app.route("/handledata_vul", methods=['POST', 'GET'])
def handledata_vul():
    
    from_ses = request.form['fromses']
    to_ses = request.form['toses']
    itsm = request.form['itsmfeed']
    itsm_protocol = request.form['itsmprotocol']
    itsm_endpoint = request.form['itsmendpoint']
    duration = request.form['duration']
    patch_groups = request.form['tags']
    template_name = request.form['templatename']
    rules = request.form['rulepackages']
    region = request.form['region']
    buck = request.form['bucketname']

    main_apply = "terraform apply -input=false -var='regions=%s' -var='patchgroupinput=%s' -var='inspectorassessmentname=%s' -var='assessmentduration=%s' -var='rulepackageselection=%s' -var='needitsm=%s' -var='protocolforitsm=%s' -var='endpointforitsm=%s' -var='sendermailID=%s' -var='receivermailID=%s' -var='bucketname=%s' -auto-approve -refresh=false -no-color" % (region, patch_groups, template_name, duration, rules, itsm, itsm_protocol, itsm_endpoint, from_ses, to_ses, buck)
    main_apply_shlex = shlex.split(main_apply)
    main_apply_process = subprocess.Popen(main_apply_shlex)

    #destroy = "terraform destroy"
    #destroy_shlex = shlex.split(destroy)
    #destroy_process = subprocess.Popen(destroy_shlex)

    return render_template("handledata_vul.html", region = region, from_ses=from_ses, to_ses=to_ses, 
        itsm=itsm, itsm_protocol=itsm_protocol, 
        itsm_endpoint=itsm_endpoint,
        patch_groups=patch_groups, template_name=template_name, rules=rules, duration=duration, buck=buck)

# Compliance
@app.route("/configdesc")
def configdesc():
    return render_template("compliancedesc.html")

@app.route("/configform")
def configform():
    return render_template("complianceform.html")

@app.route("/handledata_compliance", methods = ['POST', 'GET'])
def handledata_compliance():
    
    region = request.form['region']
    s3avail = request.form['s3avail']
    s3availbuck = request.form['s3availbuck']
    from_ses = request.form['fromses']
    to_ses = request.form['toses']
    report = request.form['report']
    itsm = request.form['itsmfeed']
    itsm_protocol = request.form['itsmprotocol']
    itsm_endpoint = request.form['itsmendpoint']
    buck = request.form['bucketname']

    main_apply = "terraform apply -input=false -var='region=%s' -var='rate=%s' -var='needitsm=%s' -var='protocolforITSM=%s' -var='endpointforITSM=%s' -var='sendermail=%s' -var='receivermail=%s' -var='source_bucket_name=%s' -var='createS3bucket=%s' -var='existingS3bucket=%s' -auto-approve -refresh=false -no-color" % (region, report, itsm, itsm_protocol, itsm_endpoint, from_ses, to_ses, buck, s3avail, s3availbuck)
    main_apply_shlex = shlex.split(main_apply)
    main_apply_process = subprocess.Popen(main_apply_shlex)

    #destroy = "terraform destroy"
    #destroy_shlex = shlex.split(destroy)
    #destroy_process = subprocess.Popen(destroy_shlex)

    return render_template("handledata_compliance.html", from_ses=from_ses, to_ses=to_ses, 
        itsm=itsm, itsm_protocol=itsm_protocol, 
        itsm_endpoint=itsm_endpoint,
        region=region, template_name=template_name, rules=rules, duration=duration, buck=buck)

# Asset
@app.route("/assetdesc")
def assetdesc():
    return render_template("assetdesc.html")

@app.route("/assetform")
def assetform():
    return render_template("assetform.html")

@app.route("/handledata_asset", methods = ["POST", "GET"])
def handledata_asset():
    return render_template("handledata_asset.html")

if __name__ == "__main__":
    app.run(host = "127.0.0.1", port = 5000)