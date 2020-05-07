from flask import Flask
from flask import render_template
from flask_mqtt import Mqtt
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO
import paho.mqtt.client as mqtt
import json
import eventlet
import subprocess
import threading
import time
import os
import signal

eventlet.monkey_patch()  

app = Flask(__name__)

app.config['MQTT_BROKER_URL'] = "broker.mqttdashboard.com"  # use the free broker from HIVEMQ
app.config['MQTT_BROKER_PORT'] = 1883  # default port for non-tls connection
app.config['MQTT_KEEPALIVE'] = 5  # set the time interval for sending a ping to the broker to 5 seconds
app.config['MQTT_TLS_ENABLED'] = False  # set TLS to disabled for testing purposes

MQTT_TOPIC = [("Packet", 0),("ttlBitrate",0)]
mqtt = Mqtt(app)
socketio = SocketIO(app)
bootstrap = Bootstrap(app)

@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    mqtt.subscribe(MQTT_TOPIC)
    
@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    print("message received " ,message.payload.decode("utf-8","ignore"))
    print("message topic=",message.topic)
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )         

@mqtt.on_log()
def handle_logging(client, userdata, level, buf):
    print(level, buf)    


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/Start")    
def run():
    subprocess.call(["sudo","python3","/home/pi/Analyzer/Packet_Analyser.py"])
    print("Done")

@app.route("/Stop")    
def stop():
    subprocess.call(["pkill" ,"-f", "Packet_Analyser.py"])
    print("Done")
     
    
if __name__ == "__main__":
    app.run(debug=True)
 
