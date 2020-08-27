from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList

import re
from datetime import datetime
from HTMLParser import HTMLParser


# strips html tags out of responses
class TagStripper(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.pageText = []

    def handle_data(self, data):
        self.pageText.append(data)

    def handle_comment(self, data):
        self.handle_data(data)

    def strip(self, html):
        self.feed(html)
        return "".join(self.pageText)


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helper = callbacks.getHelpers()
        self.context = None
        self.hosts = set()

        set.wordlist = {"password"}

        callbacks.setExtensionName("BHP Wordlist")
        callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menus = ArrayList()
        menus.add(JMenuItem("Create Wordslist", actionPerformed=self.wordlist_menu))

        return menus

    def wordslist_menu(self, event):
        traffic = self.context.getSelectedMessages()

        for traffic in traffic:
            service = traffic.getHttpService()
            host = service.getHost()

            self.hosts.add(host)

            response = traffic.getResponse()

            if response:
                self.get_words(response)

        self.display_wordlist()
        return

    def get_words(self, response):

        headers, body = response.tostring().split("\r\n\r\n", 1)

        if headers.lower().find("content-type: text") == -1:
            return

        tagStripper = TagStripper()
        pageText = tagStripper.strip(body)

        words = re.findall("[a-zA-Z]\w{2,}", pageText)

        for word in words:

            if len(word) <= 12:
                self.wordslist.add(word.lower())

        return

    def mangle(self, word):
        year = datetime.now().year
        # adds common suffixes to add to base word
        suffixes = ["", "1", "!", year]
        mangled = []

        for password in (word, word.capitalize()):
            for suffix in suffixes:
                mangled.append("%s%s" % (password, suffix))
        return mangled

    def display_wordslist(self):
        print("#!commend: Wordlist for site(s) T%s")

        for word in sorted(self.wordlist):
            for password in self.mangle(word):
                print(password)

        return
