#**********************************************************************************************
# Traffic Emulator for Network Services
# Copyright 2020 VMware, Inc
# The BSD-2 license (the "License") set forth below applies to all parts of
# the Traffic Emulator for Network Services project. You may not use this file
# except in compliance with the License.
#
# BSD-2 License
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE
#**********************************************************************************************

from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint
import argparse
from flask import request
import os
from TE_WRAP import *

app=Flask(__name__)

SWAGGER_URL = '/swagger'
API_URL = '/static/setup_te_swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,API_URL,
    config={
        'app_name': "Traffic Engine"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
print(app.root_path)


@app.route('/api/setup_te')
def setup_te():
    controller_ip = request.args['te_controller_ip']
    user = request.args['user']
    password = request.args.get('passwd', None)
    dockerhub_repo = request.args.get('dockerhub_repo', 'projects.registry.vmware.com/tens/te:v2.0')

    te_controller_obj= { 'host': controller_ip , 'user': user , 'passwd': password }

    #Check whether the controller Machine is reachable or not
    return_val = os.system("ping -c 5 -w 5 {}".format(controller_ip))
    if return_val != 0:
        return {"status" : False, "statusmessage" : "TE controller IP not reachable"}

    #ssh connection to the controller machine
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(controller_ip, username=user, password=password)
    else:
        ssh.connect(controller_ip, username=user)

    #check if python is installed in the controller machine, as it it required to run GET_AND_RUN_DOCKER_IMAGE.py file
    cmd = "which python"
    stdin,stdout,stderr = ssh.exec_command(cmd)
    out = stdout.readlines()
    if (not(out)):
        return {"status" : False, "statusmessage" : "python not installed in TE controller"}

    tens_te_obj = TensTE(te_controller_obj)
    response = tens_te_obj.setup_te(dockerhub_repo=dockerhub_repo)

    if response.get('status', False):
        flask_port = response.get('statusmessage', {}).get('flask', None)
        if flask_port:
            te_controller_swagger_ui_url = "{}:{}/swagger".format(controller_ip, flask_port)
            response['statusmessage']['te_controller_swagger_ui_url'] = te_controller_swagger_ui_url
        else:
            response['status'] = False
            response['statusmessage'] = "Unable to find Flask port"
    return response

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-fp','--flask_port',type=int, required=False, default=4000,
        help='flask port where swagger UI will run')

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    input_args = parse_arguments()
    flask_port = input_args.flask_port
    app.run(host="0.0.0.0", port=flask_port)
