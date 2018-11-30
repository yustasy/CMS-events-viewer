#!/usr/bin/python
#!/usr/bin/env python

import ssl
from pprint import pprint
import json
import websocket
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  		# отключаем предупреждение о не
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)			# достоверных сертификатах

# Функция, возвращающая авторизационный токен
def getauthkey():
    CMS_BASE = 'https://10.100.1.227:9443/api/v1/'  # Задаем основные параметры (например IP)
    CMS_HEADERS = {'Content-type': 'application/json', 'authorization': "Basic YWRtaW46QzFzY28xMjM="}  # Задаем логин-пароль (берем из postman)
    mykey = requests.post(CMS_BASE + 'authTokens', verify=False, headers=CMS_HEADERS)
    mykey.encoding = 'utf-8'  # задаем кодировку
    if mykey.status_code == 200:
        return mykey.headers['X-Cisco-CMS-Auth-Token']


class subscriber:
   def listenForever(self):
    try:

#       my_message = {"type": "message", "message": {"messageId": 1, "type": "subscribeRequest", "subscriptions": [{"index": 3, "type": "calls", "elements": ["name", "participants"]}]}}

        print(json.dumps({"type": "message", "message": {"messageId": 1, "type": "subscribeRequest", "subscriptions": [{"index": 3, "type": "calls", "elements": ["name", "participants"]}]}}))
        ws = websocket.create_connection("wss://10.100.1.227:9443/events/v1?authToken=" + getauthkey(), sslopt={"check_hostname": False})
        ws.send(json.dumps({"type": "message", "message": {"messageId": 1, "type": "subscribeRequest", "subscriptions": [{"index": 3, "type": "calls", "elements": ["name", "participants"]}]}}))
        while True:
            result = ws.recv()
            result = json.loads(result)
            print("Received '%s'" % result)

            # Функция, отвечающая на сообщения CMS
            if 'message' in result:
                Id = result["message"]["messageId"]
                print(Id)

                if result["message"]["type"] == "subscriptionUpdate":
                    state = result["message"]["subscriptions"][0]["state"]
                    if state == 'pending' or state == "active":
                        ws.send(json.dumps({"type": "messageAck", "messageAck": {"messageId": Id, "status": "success"}}))
                if result["message"]["type"] == "callListUpdate":
                    ws.send(json.dumps({"type": "messageAck", "messageAck": {"messageId": Id, "status": "success"}}))

        ws.close()
    except Exception as ex:
        print("exception: ", format(ex))


try:
    subscriber().listenForever()

except:
    print("Exception occured: ")
