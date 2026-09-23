import tudor.sensor
from .tmpl_store import TemplateStore

class CmdContext:
    pairing_data : tudor.sensor.SensorPairingData

    def __init__(self, sensor : tudor.sensor.Sensor):
        self.exit_loop = False
        self.sensor = sensor
        self.pairing_data = None
        self._tmpl_store = None

    def template_store(self) -> TemplateStore:
        #Lazily open the host-side label<->TUID registry for this sensor (keyed by sensor id).
        if self._tmpl_store is None:
            self._tmpl_store = TemplateStore(self.sensor.id)
        return self._tmpl_store