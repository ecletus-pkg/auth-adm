package authadm

import (
	"time"

	"github.com/ecletus/fragment"

	"github.com/moisespsena-go/aorm"
)

type AuthAdmIpRule struct {
	aorm.AuditedModel

	ProtectorID string `gorm:"size:24;index"`

	Enabled bool
	Ip      string
}

type AuthAdmTimeRange struct {
	aorm.KeyStringSerial

	Enabled bool

	From, To time.Time

	RuleID string `gorm:"size:24;index"`
}

type AuthAdmDayRule struct {
	aorm.AuditedModel

	Enabled bool

	Sun, Mon, Tue, Wed, Thu, Fri, Sat bool

	ProtectorID string `gorm:"size:24;index"`

	Times []AuthAdmTimeRange `gorm:"foreignkey:RuleID"`
}

type AuthAdmProtector struct {
	fragment.FormFragmentModel

	AutoLogout bool
	IpRules    []AuthAdmIpRule  `gorm:"foreignkey:ProtectorID"`
	DayRules   []AuthAdmDayRule `gorm:"foreignkey:ProtectorID"`
}
