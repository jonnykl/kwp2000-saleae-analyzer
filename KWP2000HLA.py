
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting
from enum import Enum


class State(Enum):
    PARSE_FORMAT = 1
    PARSE_DST_ADDR = 2
    PARSE_SRC_ADDR = 3
    PARSE_LENGTH = 4
    PARSE_SERVICE_ID = 5
    PARSE_PARAMS = 6
    PARSE_CHECKSUM = 7


class KWP2000:
    service_ids = {
        0x10: "startDiagnosticScan",
        0x11: "ecuReset",
        0x12: "readFreezeFrameData",
        0x13: "readDiagnosticTroubleCodes",
        0x14: "clearDiagnosticInformation",
        0x17: "readStatusOfDiagnosticTroubleCodes",
        0x18: "readDiagnosticTroubleCodesByStatus",
        0x1A: "readEcuIdentification",
        0x20: "stopDiagnosticSession",
        0x21: "readDataByLocalIdentifier",
        0x22: "readDataByCommonIdentifier",
        0x23: "readMemoryByAddress",
        0x26: "setDataRes",
        0x27: "securityAccess",
        0x2C: "dynamicallyDefineLocalIdentifier",
        0x2E: "writeDataByCommonIdentifier",
        0x2F: "inputOutputControlByCommonIdentifier",
        0x30: "inputOutputControlByLocalIdentifier",
        0x31: "startRoutineByLocalIdentifier",
        0x32: "stopRoutineByLocalIdentifier",
        0x33: "requestRoutineResultsByLocalIdentifier",
        0x34: "requestDownload",
        0x35: "requestUpload",
        0x36: "transferData",
        0x37: "requestTransferExit",
        0x38: "startRoutineByAddress",
        0x39: "stopRoutineByAddress",
        0x3A: "requestRoutineResultsByAddress",
        0x3B: "writeDataByLocalIdentifier",
        0x3D: "writeMemoryByAddress",
        0x3E: "testerPresent",
        0x80: "escCode",
        0x81: "startCommunication",
        0x82: "stopCommunication",
        0x83: "accessTimingParameter"
    }

    @staticmethod
    def get_service_by_id(service_id):
        if service_id == 0x7F:
            return "negativeResponse"
        else:
            return KWP2000.service_ids.get(service_id & ~0x40, "unknown")


class KWP2000HLA(HighLevelAnalyzer):
    skip_bytes = NumberSetting(min_value=0)

    result_types = {
        "KWP-2000": {
            "format": "{{data.service}}: {{data.params}}"
        },
        "KWP-2000 error": {
            "format": "error: {{data.error}}"
        }
    }

    def __init__(self):
        self._state = State.PARSE_FORMAT
        self._skip = int(self.skip_bytes)
        self._length = 0
        self._dst_addr = 0
        self._src_addr = 0
        self._service_id = 0
        self._params = []
        self._checksum = 0
        self._start_time = None
        self._end_time = None
        self._valid = False

    def update_checksum(self, data):
        self._checksum = (self._checksum + data) & 0xFF

    def decode(self, frame: AnalyzerFrame):
        if self._skip > 0:
            self._skip -= 1
            return None
        
        if "error" in frame.data:
            return None

        data = frame.data["data"][0]
        update_checksum = True

        if self._state == State.PARSE_FORMAT:
            self._params = []
            self._checksum = 0
            self._start_time = frame.start_time
            self._valid = False

            if (data & 0xC0) == 0:
                self._length = data & 0x3F
                self._state = State.PARSE_LENGTH if self._length == 0 else State.PARSE_SERVICE_ID
            elif (data & 0xC0) == 0x40:
                self._state = State.PARSE_FORMAT
                return AnalyzerFrame("KWP-2000 error", frame.start_time, frame.end_time, {
                    "error": "unsupported CARB format"
                })
            else:
                self._length = data & 0x3F
                self._state = State.PARSE_DST_ADDR
        elif self._state == State.PARSE_DST_ADDR:
            self._dst_addr = data
            self._state = State.PARSE_SRC_ADDR
        elif self._state == State.PARSE_SRC_ADDR:
            self._src_addr = data
            self._state = State.PARSE_LENGTH if self._length == 0 else State.PARSE_SERVICE_ID
        elif self._state == State.PARSE_LENGTH:
            self._length = data
            if self._length == 0:
                self._state = State.PARSE_FORMAT
                return AnalyzerFrame("KWP-2000 error", frame.start_time, frame.end_time, {
                    "error": "invalid length"
                })

            self._state = State.PARSE_SERVICE_ID
        elif self._state == State.PARSE_SERVICE_ID:
            self._service_id = data
            self._state = State.PARSE_CHECKSUM if self._length == 1 else State.PARSE_PARAMS
        elif self._state == State.PARSE_PARAMS:
            self._params.append(data)
            self._state = State.PARSE_CHECKSUM if len(self._params) == self._length-1 else State.PARSE_PARAMS
        elif self._state == State.PARSE_CHECKSUM:
            if data != self._checksum:
                self._state = State.PARSE_FORMAT
                return AnalyzerFrame("KWP-2000 error", frame.start_time, frame.end_time, {
                    "error": "invalid checksum"
                })

            self._end_time = frame.end_time
            self._state = State.PARSE_FORMAT
            self._valid = True
            update_checksum = False
        else:
            raise Exception("internal error: unknown state")

        if update_checksum:
            self.update_checksum(data)

        if self._valid:
            self._valid = False
            return AnalyzerFrame("KWP-2000", self._start_time, self._end_time, {
                "dst": bytes([self._dst_addr]),
                "src": bytes([self._src_addr]),
                "service_id": bytes([self._service_id]),
                "service": KWP2000.get_service_by_id(self._service_id),
                "params": bytes(self._params),
                "checksum": bytes([self._checksum])
            })

        return None

