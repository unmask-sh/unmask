package settings

import (
	"log"

	"gopkg.in/yaml.v3"
)

// warnRemovedGlobalPassthrough: `global.passthrough` was the operator-facing
// pass-through switch until 0.1.51.  It handed every visitor a pass cookie, so
// the measurement an operator turned it on to collect decayed, the cookies
// outlived the mode, and it never let anyone past a deny or a ban anyway.
// Monitor mode is the one switch now.  The generic unknown-key warning would
// read as harmless; an operator who had this ON as an emergency hold needs to
// know that enforcement is back and where the switch went.
func warnRemovedGlobalPassthrough(resolved string, raw []byte) {
	var probe struct {
		Global struct {
			Passthrough *bool `yaml:"passthrough"`
		} `yaml:"global"`
	}
	if yaml.Unmarshal(raw, &probe) != nil || probe.Global.Passthrough == nil {
		return
	}
	if *probe.Global.Passthrough {
		log.Printf("unmask: config %s still sets global.passthrough: true -- REMOVED in 0.1.51 and ignored, so "+
			"enforcement is ON. Monitor mode (challenge.default.observe_only, the Operating-mode tab) is the one "+
			"switch that lets every visitor through while recording the judgement; on a module install it is "+
			"rendered into nginx, so run render-nginx + reload after turning it on. The over-block breaker keeps "+
			"its own over_block_breaker.auto_passthrough. Delete the `passthrough:` line to silence this.", resolved)
		return
	}
	log.Printf("unmask: config %s still carries global.passthrough (removed in 0.1.51, ignored). "+
		"Delete the line; monitor mode (challenge.default.observe_only) is the switch now.", resolved)
}
