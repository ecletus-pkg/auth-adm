package authadm

import (
	"time"

	"github.com/ecletus/fragment"

	"github.com/moisespsena-go/aorm"
)

type AuthAdmLoginIpRule struct {
	aorm.AuditedModel

	ProtectorID string `gorm:"size:24;index"`

	Enabled bool
	Ip      string
}

type AuthAdmTimeRange struct {
	aorm.KeyStringSerial

	Enabled  bool
	From, To time.Time

	RuleID string `gorm:"size:24;index"`
}

type AuthAdmLoginDayRule struct {
	aorm.AuditedModel

	Enabled,
	Sun, Mon, Tue, Wed,
	Thu, Fri, Sat bool

	ProtectorID string `gorm:"size:24;index"`

	Times []AuthAdmTimeRange `gorm:"foreignkey:RuleID"`
}

type AuthAdmProtector struct {
	fragment.FormFragmentModel

	AutoLogout bool
	IpRules    []AuthAdmLoginIpRule  `gorm:"foreignkey:ProtectorID"`
	DayRules   []AuthAdmLoginDayRule `gorm:"foreignkey:ProtectorID"`
}

type AuthAdmTime struct {
	aorm.KeyStringSerial

	Hour, Minute, Second int

	AutoUpdaterID string `gorm:"size:24;index"`
}

type AuthAdmMail struct {
	aorm.AuditedModel

	Address string

	AutoUpdaterID string `gorm:"size:24;index"`
}

type AuthAdmPasswordsAutoUpdater struct {
	fragment.FormFragmentModel

	AutoLogout bool

	Sun, Mon, Tue, Wed,
	Thu, Fri, Sat bool

	Times        []AuthAdmTime `gorm:"foreignkey:AutoUpdaterID"`
	Notificators []AuthAdmMail `gorm:"foreignkey:AutoUpdaterID"`
}
