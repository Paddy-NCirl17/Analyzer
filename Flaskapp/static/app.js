$(document).ready(function(){
    /* Define Broker */
    const BROKER = 'broker.mqttdashboard.com';
    const PORT = 8000;

    /* client */
    const CLIENTID = 'PacketClient';
    const TOPIC = 'Packet/#'
    client = new Paho.MQTT.Client(BROKER, PORT, CLIENTID);
    client.connect({onSuccess:onConnect});
    client.onMessageArrived = onMessageArrived;
    
    // called when the client connects
    function onConnect() {
        // Once a connection has been made, make a subscription and send a message.
        console.log("onConnectPacket");
        client.subscribe(TOPIC);
    }
    
    function onMessageArrived(message) {
        /*console.log("onMessageArrived:"+message.payloadString);*/
        let readings = JSON.parse(message.payloadString);
        console.log(readings['id'])
        var tr;
            tr = $('<tr/>');
            tr.append("<td>" + (readings['type'])+"</td>");
            tr.append("<td>" + (readings['id'])+"</td>");
            tr.append("<td>" + (readings['seq'])+"</td>");
            tr.append("<td>" + (readings['time'])+"</td>");
            tr.append("<td>" + (readings['src'])+"</td>");
            tr.append("<td>" + (readings['dst'])+"</td>");
            tr.append("<td>" + (readings['size'])+"</td>");
            tr.append("<td>" + (readings['BR'])+"</td>");
            tr.append("<td>" + (readings['drop'])+"</td>");
        
            $('table').prepend(tr); 
    }

    
  
    const CLIENTID1 = 'ttlBitrateClient';
    const TOPIC1 = 'ttlBitrate/#'
    client1 = new Paho.MQTT.Client(BROKER, PORT, CLIENTID1);
    client1.connect({onSuccess:onConnect1});
    client1.onMessageArrived = onMessageArrived1;
    
    // called when the client connects
    function onConnect1() {
        // Once a connection has been made, make a subscription and send a message.
        /*console.log("onConnectBitRate");*/
        client1.subscribe(TOPIC1);
    }
    
    function onMessageArrived1(message) {
        /*console.log("onMessageArrived:"+message.payloadString);*/
        let readings = JSON.parse(message.payloadString);
        $('#ttlbR').text(readings['ttlBR']);                
    }
    
    
  })       

