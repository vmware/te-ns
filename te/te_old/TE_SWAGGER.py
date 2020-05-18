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


@app.route('/api/setup_te')
def setup_te():
    controller_ip = request.args['te_controller_ip']
    user = request.args['user']
    password = request.args['passwd']
    
    te_controller_obj= { 'host': controller_ip , 'user': user , 'passwd': password }

    #Check whether the controller Machine is reachable or not
    return_val = os.system("ping -c 5 -w 5 {}".format(controller_ip))
    if return_val != 0:
        return {"status" : False, "statusmessage" : "TE controller IP not reachable"}
    
    #ssh connection to the controller machine
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(controller_ip, username=user, password=password)

    #check if python is installed in the controller machine, as it it required to run GET_AND_RUN_DOCKER_IMAGE.py file
    cmd = "which python"
    stdin,stdout,stderr = ssh.exec_command(cmd)
    out = stdout.readlines()
    if (not(out)):
        return {"status" : False, "statusmessage" : "python not installed in TE controller"} 
    
    avi_te_obj = AviTE(te_controller_obj)
    response = avi_te_obj.setup_te(repo_path= input_args.repo_path, path_to_python_file_to_copy=os.path.dirname(os.path.abspath(__file__)))

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
    parser.add_argument('-rp','--repo_path',type=str, required=False,default='stable-repo',
        help = 'Repo path to build up the TE')
    parser.add_argument('-fp','--flask_port',type=int, required=False,default=5000,
            help='flask port where swagger UI will run')
    
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    input_args = parse_arguments()
    repo_path = input_args.repo_path
    flask_port = input_args.flask_port
    app.run(host = '0.0.0.0', port = flask_port)

