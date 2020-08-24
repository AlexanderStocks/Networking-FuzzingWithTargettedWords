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

# extends IIntruderPayloadGenerator which declares 3 methods...
# hasMorePayloads - checks if reached payload limit
# getNextPayload - receives payload from http request and fuzzes it
# reset - resets the factory
class BHPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = 10
        self.num_iterations = 0

        return

    def hasMorePayloads(self):
        if self.num_iterations == self.max_payloads:
            return False
        else:
            return True

    def getNextPayload(self, current_payload):

        payload = "".join(chr(x) for x in current_payload) # convert byte array to string

        payload = self.mutate_payload(payload)

        self.num_iterations += 1

        return payload

    def reset(self):
        self.num_iterations = 0
        return




