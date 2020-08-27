from burp import IBurpExtender  # requirement for every extension to burp
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
import random


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
        self.extender = extender
        self.helpers = extender._helpers
        self.attack = attack
        self.maxPayloads = 10
        self.iters = 0

        return

    def hasMorePayloads(self):
        if self.iters == self.maxPayloads:
            return False
        else:
            return True

    def getNextPayload(self, current_payload):

        payload = "".join(chr(x) for x in current_payload)  # convert byte array to string

        payload = self.mutate(payload)

        self.num_iterations += 1

        return payload

    def reset(self):
        self.iters = 0
        return

    def mutate(self, original_payload):
        picker = random.randint(1, 3)

        offset = random.randint(0, len(original_payload) - 1)
        payload = original_payload[:offset]

        # try SQL Injection
        if picker == 1:
            payload += "'"

        # try XSS
        if picker == 2:
            payload += "<script>alert('BHP!);</script>"

        # repeat some of the payload
        if picker == 3:
            chunkLen = random.randint(len(payload[offset:]), len(payload) - 1)
            repeater = random.randint(1, 10)

            for i in range(repeater):
                payload += original_payload[offset:offset + chunkLen]

        payload += original_payload[offset:]

        return payload
