package headscale

import "gorm.io/gorm"

var (
	MachineRegisteredTrigger func(machine *Machine)
	MachineExpiredTrigger    func(machine *Machine)
)

func (h *Headscale) DB() *gorm.DB {
	return h.db
}

func (h *Headscale) ExpireEphemeralNodes(milliSeconds int64) {
	h.expireEphemeralNodes(milliSeconds)
}

func (h *Headscale) ScheduledDERPMapUpdateWorker(cancelChan <-chan struct{}) {
	h.scheduledDERPMapUpdateWorker(cancelChan)
}
