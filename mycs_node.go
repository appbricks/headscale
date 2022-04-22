package headscale

import (
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

var (
	MachineRegisteredTrigger func(machine *Machine)
	MachineExpiredTrigger    func(machine *Machine)

	MapTailscaleDNSConfig func(dnsConfig *tailcfg.DNSConfig)
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
