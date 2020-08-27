import urllib
from urllib import parse

from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import socket
import json
import re
import base64

# your bing api key here
bingKey = "KEY"


# allows users to right click for context in burp
class BurpExtension(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallback(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHeopers()
        self.context = None

        callbacks.setExtensionName("BING")
        callbacks.registerContectMenuFactory(self)

        return

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menus = ArrayList()
        menus.add(JMenuItem("Send to Bing", actionPerformed=self.bing_menu))
        return menus

    def bing_menu(self, event):
        # get all highlighted messages
        traffic = self.context.getSelectedMessages()

        print("%d requests highlighted" % len(traffic))

        for traffic in traffic:
            service = traffic.getHttpService()
            host = service.getHost()

            print("User selected host: %s" % host)

            self.search(host)

        return

    def search(self, host):
        maybeIP = re.match("[0-9]+(?:\.[0-9]+){3}", host)

        if maybeIP:
            IPAddress = host
            domain = False
        else:
            IPAddress = socket.gethostbyname(host)
            domain = True

        # search bing for virtual hosts with same IP
        query = "'ip:%s'" % IPAddress
        self.queryBing(query)

        if domain:
            query = "'domain:%s'" % host
            self.queryBing(query)

    def queryBing(self, query):

        print("Perfoming bing search: %s" % query)

        quotedQuery = urllib.parse.quote(query)

        httpReq = "GET https://api.datamarket.azure.com/Bing/Search/Web?$format=json&$top=20&QUery=%s HTTP/1.1\r\n" % quotedQuery
        httpReq += "Host: api.datamarket.azure.com\r\n"
        httpReq += "Connection: close\r\n"
        httpReq += "Authorization: Basic %s\r\n" % base64.b64encode(":%s" % bingKey)
        httpReq += "User_Agent: Blackhat Python\r\n\r\n"

        # send http request to microsoft servers
        jsonBody = self._callbacks.makeHttpRequest("api.datamarket.azure.com", 443, True, httpReq).tostring()
        # split off headers
        jsonBody = jsonBody.split("\r\n\r\n", 1)[1]

        try:
            r = json.loads(jsonBody)
            if len(r["d"]["results"]):
                for site in r["d"]["results"]:
                    print("*" * 100)
                    print(site["Title"])
                    print(site["Url"])
                    print(site["Description"])
                    print("*" * 100)

                    j_url = URL(site["Url"])

            if not self._callbacks.includeInScope(j_url):
                print("Adding to Burp Scope")
                self._callbacks.includeInScope(j_url)
        except LookupError as e:
            print("No results from bing")
            pass

        return


