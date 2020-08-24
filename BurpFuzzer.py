from burp import IBurpExtender # requirement for every extension to burp
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)

        return

    def getGeneratorName(self):
        return "Payload Generator"

    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)



