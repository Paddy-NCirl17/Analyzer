from flask import Flask
from flask import render_template
from flask import redirect
from flask_mqtt import Mqtt
from flask_bootstrap import Bootstrap
import paho.mqtt.client as mqtt
import json
import subprocess
import time
import os
import signal

app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')


@app.route("/Start")    
def run():
    subprocess.call(["sudo","python3","/home/pi/Analyzer/Packet_Analyser.py"])
    return redirect('/')

@app.route("/Stop")    
def stop():
    subprocess.call(["sudo","pkill" ,"-f", "Packet_Analyser.py"])
    time.sleep(300)
    return render_template('index.html')
     
    
if __name__ == "__main__":
    app.run()
 
