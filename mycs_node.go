package headscale

import "gorm.io/gorm"

func (h *Headscale) DB() *gorm.DB {
	return h.db
}

func (h *Headscale) WatchForKVUpdates(milliSeconds int64) {
	h.watchForKVUpdates(milliSeconds)
}

func (h *Headscale) ExpireEphemeralNodes(milliSeconds int64) {
	h.expireEphemeralNodes(milliSeconds)
}