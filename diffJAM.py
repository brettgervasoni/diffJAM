# Burp Extension - Diff JAM
# Brett Gervasoni <brett.gervasoni@nccgroup.com>
#
# Adds a new tab to the Response pane of Repeater, which shows the differences
# in the previous and current response.
#
# A new context menu entry is also created to manually turn on, or off the extension.
#
# Note: The extension is turned off by default (right click a IMessageEditor pane and turn on).

import json
import difflib

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IContextMenuFactory

# Java imports
from javax.swing import JMenuItem
from java.util import List, ArrayList

menuItems = {
    False: "Turn on Diff JAM",
    True:  "Turn off Diff JAM"
}

_enabled = False

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName('Diff JAM')
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)

        return

    def createNewInstance(self, controller, editable): 
        return DiffJAMTab(self, controller, editable)

    def createMenuItems(self, IContextMenuInvocation):
        global _enabled
        menuItemList = ArrayList()
        menuItemList.add(JMenuItem(menuItems[_enabled], actionPerformed = self.onClick))

        return menuItemList

    def onClick(self, event):
        global _enabled
        _enabled = not _enabled

class DiffJAMTab(IMessageEditorTab):
    supportedContentTypes = [
        "application/json",
        "text/json",
        "text/x-json",
        "text/html"
    ]

    currentContent = ""
    previousContent = ""

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(self._editable)

        return

    def getTabCaption(self):
        return "Diff"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        #if response timestamp was not within latest few seconds, dont enable it

        #based on user setting
        global _enabled
        if _enabled == False:
            return False

        if content is None or content == "":
            return False

        #setting up, log first
        if self.currentContent == "":
            self.currentContent = content
            return False
        #set previous to current, and current to latest
        if self.previousContent == "":
            self.previousContent = self.currentContent
            self.currentContent = content

        #get as string
        currentContentString = self.currentContent.tostring()

        if content.tostring() != currentContentString:
            self.previousContent = self.currentContent
            self.currentContent = content

        #otherwise, check if its a supported content-type
        if isRequest == False and self._editable == False:
            #check content-type header
            r = self._helpers.analyzeResponse(content)
            for header in r.getHeaders():
                if header.lower().startswith("content-type:"):
                    contentType = header.split(":")[1].lower()

                    for allowedType in self.supportedContentTypes:
                        if contentType.find(allowedType) > 0:
                            return True

            #if the content-type is invalid, check for magic chars, as it will be comparable
            if self.checkForJson(content, isRequest):
                return True

        return False

    def setMessage(self, content, isRequest):
        self._currentMessage = content
        comparison = ""

        #get as string
        previousContentString = self.previousContent.tostring()

        #do processing
        if previousContentString != "" and content != None:
            a = previousContentString
            b = content.tostring()

            #check for json, if so, try and decode it
            #update a if required
            if self.checkForJson(self.previousContent, isRequest):
                #is json, then decode it
                a = self.jsonDecode(self.previousContent, isRequest)

            #update b if required
            if self.checkForJson(content, isRequest):
                #is json, then decode it
                b = self.jsonDecode(content, isRequest)

            previousPtr = ''
            threshold = 0
            diff = difflib.ndiff(a.split("\n"), b.split("\n"))
            for line in diff:
                #leaving out '?' lines as they are not required and makes it pretty messy
                #' ' lines are where the content is the same
                if line[0] != "?" and line[0] != ' ':
                    #format line, strip leading/trailing whitespace from line
                    comparison = comparison+line[0]+" "+line[1:].strip()+"\n"

                    #group lines based on -, + chars
                    if previousPtr != line[0]:
                        threshold += 1

                    if previousPtr != line[0] and threshold >= 2:
                        comparison = comparison+"\n"
                        threshold = 0

                    previousPtr = line[0]


        if comparison == "":
            comparison = "No changes."

        self._txtInput.setEditable(True)
        self._txtInput.setText(comparison)

        return

    #in future, ideally check for content-types too
    def checkForJson(self, content, isRequest):
        jsonMagicMark = ['{', '[', '[{']

        if isRequest:
            r = self._helpers.analyzeRequest(content)
        else:
            r = self._helpers.analyzeResponse(content)

        msg = content[r.getBodyOffset():].tostring().strip()

        if len(msg) > 2 and msg[0] in jsonMagicMark:
            return True
        else:
            return False

    def jsonDecode(self, content, isRequest): 
        if isRequest:
            r = self._helpers.analyzeRequest(content)
        else:
            r = self._helpers.analyzeResponse(content)

        msg = content[r.getBodyOffset():].tostring()

        try:
            boundary = min(
                        msg.index('{') if '{' in msg else len(msg),
                        msg.index('[') if '[' in msg else len(msg)
                      )
        except ValueError:
            print("Sure this is JSON?")
            return

        garbage = msg[:boundary]
        clean = msg[boundary:]

        try:
            pretty_msg = garbage.strip() + '\n' + json.dumps(json.loads(clean), indent=4)
        except:
            print("Problem parsing data in response body")
            pretty_msg = garbage + clean

        #add in headers
        headers = ""
        for header in r.getHeaders():
            headers += header + "\n"

        pretty_msg = headers + pretty_msg
        return pretty_msg

    def getMessage(self): 
        return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
