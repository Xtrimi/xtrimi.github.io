import time
import hashlib
from flask import Flask, g, request, render_template, make_response, redirect, url_for
app = Flask(__name__)

@app.before_request
def auth():
    if not request.cookies.get('session'):
        res = make_response(redirect(url_for('root')))
        g.session = hashlib.md5(str(time.time()).encode()).hexdigest()
        res.set_cookie('session', g.session)
        return res

    g.session = request.cookies.get('session')

def getctx():
    try:
        with open(f'./tmp/{g.session}', mode='a+', encoding='utf8') as f:
            f.seek(0)
            ctx = f.read()
    except:
        with open(f'./tmp/{g.session}', mode='r', encoding='utf8') as f:
            ctx = f.read()
            
    return 'Hello World' if not ctx else ctx

@app.route('/')
def root():
    return render_template('index.html',text = getctx())

@app.route('/profile')
def profile():
    return render_template('profile.html', text = getctx())

@app.route('/save', methods=['POST'])
def save():
    with open(f'./tmp/{g.session}', mode='w', encoding='utf8') as f:
        f.write(request.form['text'])
    return 'ok'

if __name__ == '__main__':
    app.run('0.0.0.0', 80)