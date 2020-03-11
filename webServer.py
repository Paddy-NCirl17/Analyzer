from flask import Flask, render_template
import datetime
app = Flask(__name__)
@app.route("/")
def hello():
   now = datetime.datetime.now()
   timeString = now.strftime("%Y-%m-%d %H:%M")
   templateData = {
      'title' : 'HELLO!',
      'time': timeString,
      'Ip_Address': ipv4_packet.source
      }

   return render_template('index.html', **templateData)
if __name__ == "__main__":
   app.run(host='192.168.8.110', port=80, debug=True)
