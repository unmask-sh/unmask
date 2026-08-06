package settings

import (
	"log"

	"gopkg.in/yaml.v3"
)

// warnRemovedChallengeAll: say what a leftover `challenge_targets.all` key
// actually costs, instead of letting it hide inside the generic
// "unrecognized or misplaced keys" line.
//
// 0.1.19 removed the key, and the migration story was "the bucket actions
// already challenge every no-match request, so a default install behaves
// identically".  True for the challenge itself -- but being a *target* is
// also an input to other decisions (per-row actions, deny), and an operator
// who ran `all: true` had every UA in the target set.  On one install the
// generic warning read as harmless while a crawler the operator believed
// blocked kept itself passed, and the report that came back said exactly
// this: the warning looked ignorable, and it was describing a downgrade.
//
// Warn only.  The key stays ignored -- no behavior returns
// (feedback_no_user_rescue) -- but the operator is told what changed and
// what the replacement is.
func warnRemovedChallengeAll(resolved string, raw []byte) {
	var probe struct {
		Nginx struct {
			ChallengeTargets struct {
				All *bool `yaml:"all"`
			} `yaml:"challenge_targets"`
		} `yaml:"nginx"`
	}
	if yaml.Unmarshal(raw, &probe) != nil {
		return
	}
	if probe.Nginx.ChallengeTargets.All == nil {
		return
	}
	if *probe.Nginx.ChallengeTargets.All {
		log.Printf("unmask: config %s still sets challenge_targets.all: true -- REMOVED in 0.1.19 and ignored. "+
			"Every UA used to be a challenge target under it; now only explicit rows are, and everything else "+
			"follows the Operating-mode buckets (default: still challenged). The difference that matters: a "+
			"crawler you mean to BLOCK is not blocked by being challenged -- anything that can obtain or rebind "+
			"a pass cookie walks through. Give it an explicit UA row with action \"deny\" (enforced before the "+
			"cookie since 0.1.21), then render-nginx + reload. Delete the `all:` line to silence this.", resolved)
		return
	}
	log.Printf("unmask: config %s still carries challenge_targets.all (removed in 0.1.19, ignored). "+
		"Delete the line; the Operating-mode buckets decide the no-match posture now.", resolved)
}
