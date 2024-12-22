from flask import *
import subprocess
import os
app = Flask(__name__)

@app.route("/")
def hello():
    return render_template('index.html')

@app.route("/test-find-panel")
def test_find_panel():
    find_query=['find', '.']
    for key, value in request.args.items():
        find_query.append('-'+key)
        find_query.append(value)
    find_result=subprocess.run(find_query, stdout=subprocess.PIPE).stdout
    return find_result

@app.route("/getimage")
def getimage():
    img_name = request.args.get('img')
    if img_name:
        img_path = 'static/'+img_name
        if os.path.isfile(img_path):
            return send_file(img_path)
        else:
            abort(404, description="Image not found")
    else:
        return "No image specified", 400

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=13370, debug=True) 