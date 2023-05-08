from flask import Flask, jsonify, request
import  os
app = Flask(__name__)
@app.route('/', methods = ['GET', 'POST'])
def home():
    if(request.method == 'GET'):
        data = "Get is not supported"
        return jsonify({'data': data})

@app.route('/upload_file', methods = ['GET', 'POST'])
def home_proxy():
    if(request.method == 'POST'):
        temp_list = [item for item in request.form.keys()][0].split('.')
        temp_list.pop(-1)
        file_name = '.'.join(temp_list)
        temp_path = request.form[file_name + '.path'].split('/')
        temp_path.pop(-1)
        file_dir_path =  '/'.join(temp_path)
        file_path = file_dir_path + '/' + file_name
        print(file_path)
        print(file_name)
        if os.path.exists(file_path):
            out = os.popen('md5sum %s' %file_path).read()
            md5sum = out.split(' ')[0]
            if md5sum != request.form[file_name +'.md5']:
                try:
                    out = os.system('rm ' +  file_path)
                    out = os.system('mv %s %s' %(request.form[file_name \
                                                 + '.path'],file_path))
                    out = os.system('chmod 744 %s' %file_path)
                    if out != 0 :
                        return({'status': "Unable to delete TEDP docker"})
                except Exception as e:
                    return({'status': "Unable to delete TEDP docker"})
            else:
                out = os.system('rm %s' %request.form[file_name + '.path'])
                return jsonify({'status': "Upload Successful"})
            return jsonify({'status': "Upload Successful"})
        else:
            out = os.system('mv %s %s' %(request.form[file_name + '.path'],file_path))
            out = os.system('chmod 744 %s' %file_path)
            return jsonify({'status': "Upload Successful"})
    else:
        return jsonify({"data": "Only Post Allowed"})

if __name__ == '__main__':
    app.run(port=5007 ,debug = True)
