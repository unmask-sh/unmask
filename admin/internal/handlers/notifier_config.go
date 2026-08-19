package handlers

import (
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// NotifierConfigFrom assembles the runtime webhook-notifier config from
// settings.  One function for the daemon startup and the post-save hot-swap,
// so the __hostname__ expansion in the site label cannot exist on one path
// and not the other.  hostID is the RESOLVED host id (Handler.HostID /
// resolveHostID), not the raw server.host_id setting.
func NotifierConfigFrom(n settings.Notifications, hostID string) notifier.Config {
	return notifier.Config{
		Disabled:            n.Disabled,
		URL:                 n.URL,
		Format:              n.Format,
		Sites:               settings.ExpandHostPlaceholder(n.SiteLabel, hostID),
		BanEvents:           n.BanEvents,
		ChallengeBurst:      n.ChallengeBurst,
		BurstThresholdPer5m: n.BurstThresholdPer5m,
		WebhookDisabled:     n.WebhookDisabled,
		MailDisabled:        n.MailDisabled,
		MailTo:              n.MailToResolved(),
	}
}

// MailConfigFrom assembles the runtime SMTP config from settings, expanding
// __hostname__ in the From display name.  Same single-assembly rationale as
// NotifierConfigFrom.
func MailConfigFrom(s settings.SMTP, hostID string) mail.Config {
	return mail.Config{
		Host:               s.Host,
		Port:               s.Port,
		Username:           s.Username,
		Password:           s.Password,
		FromAddress:        s.FromAddress,
		FromName:           settings.ExpandHostPlaceholder(s.FromName, hostID),
		StartTLS:           s.StartTLS,
		InsecureSkipVerify: s.InsecureSkipVerify,
	}
}
