import os, json

from flask import Flask
from flask import  render_template
app = Flask(__name__)

ALL_STATUS = ['RUNNING','IDLE']

stat = 'IDLE'
proc = None

@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/dir_tree')
def dir_tree():
    root = {'text': 'root', 'nodes':[ {'text':i, 'nodes':[]} for i in os.listdir('pcap/')]}
    return json.dumps(root)

@app.route('/status')
def session_status():
    return json.dumps({'ret':0, 'status':stat})

@app.route('/output')
def fetch_output():
    if None is not proc and stat == 'RUNNING':
        return json.dumps({'ret':0, 'stdout':'', 'stderr': ''})
    else:
        return json.dumps({'ret': -1})

@app.route('/submit', methods=['POST'])
def submit_code():
    pass

if __name__ == '__main__':
    app.run()
