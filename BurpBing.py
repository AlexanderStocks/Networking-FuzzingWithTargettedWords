from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem

from py4j.java_gateway import JavaGateway
from py4j.java_gateway import java_import

gateway = JavaGateway()

jList = gateway.jvm.java.util.List()
jArrayList = gateway.jvm.java.util.ArrayList()
url = gateway.jvm.java.net.URL()

import socket
import urllib3
import json
import re
import base64

# your bing api key here
bing_api_key = "KEY"


# allows users to right click for context in burp
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallback(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHeopers()
        self.context = None

        callbacks.setExtensionName("BING")
        callbacks.registerContectMenuFactory(self)

        return

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = gateway.jvm.java.util.ArrayList()
        menu_list.add(JMenuItem("Send to Bing", actionPerformed=self.bing_menu))
        return menu_list

    def bing_menu(self, event):
        # get all highlighted messages
        http_traffic = self.context.getSelectedMessages()

        print("%d requests highlighted" % len(http_traffic))

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()

            print("User selected host: %s" % host)

            self.bing_search(host)

        return

    def bing_search(self, host):
        is_ip = re.match("[0-9]+(?:\.[0-9]+){3}", host)

        if is_ip:
            ip_address = host
            domain = False
        else:
            ip_address = socket.gethostbyname(host)
            domain = True

        # search bing for virtual hosts with same IP
        bing_query_string = "'ip:%s'" % ip_address
        self.bing_query(bing_query_string)

        if domain:
            bing_query_string = "'domain:%s'" % host
            self.bing_query(bing_query_string)
