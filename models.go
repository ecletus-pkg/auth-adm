package authadm

import (
	"fmt"
	"reflect"
	"time"

	time_helpers "github.com/moisespsena-go/time-helpers"

	"github.com/moisespsena-go/iputils"

	"github.com/ecletus/core"
	"github.com/ecletus/validations"

	"github.com/ecletus-pkg/user"

	"github.com/ecletus/fragment"

	"github.com/moisespsena-go/aorm"
	"github.com/moisespsena-go/bid"
)

var (
	userType          = reflect.TypeOf(user.User{})
	timeAttributesKey = group + ":models.AuthAdmTimeRange.Times.attributes."
)

type AuthAdmUserProtector struct {
	fragment.FragmentModel

	ProtectorID bid.BID `sql:"index"`
	Protector   *AuthAdmProtector

	User *user.User `sql:"foreignkey:ID"`
}

func (AuthAdmUserProtector) GetAormInlinePreloadFields(scope *aorm.Scope) []string {
	if reflect.TypeOf(scope.Value).Elem() == userType {
		return []string{"*", "Protector"}
	}
	return []string{"*", "User"}
}

func (p AuthAdmUserProtector) String() string {
	if p.User != nil {
		return p.User.String()
	}
	return "[no value]"
}

type AuthAdmLoginIpRule struct {
	aorm.AuditedModel

	ProtectorID bid.BID `sql:"index"`

	Enabled bool
	Ip      iputils.IPRange
}

func (this AuthAdmLoginIpRule) String() string {
	return string(this.Ip)
}

func (this AuthAdmLoginIpRule) BeforeSave() (err error) {
	if string(this.Ip) == "" {
		return fmt.Errorf("IP is blank")
	}
	_, err = this.Ip.Range()
	return
}

type AuthAdmTimeRange struct {
	aorm.BIDSerial

	From, To string

	RuleID string `sql:"size:24;index"`
}

func (this AuthAdmTimeRange) Times(now time.Time) (From, To time.Time) {
	return time_helpers.MustParseTime(now, this.From), time_helpers.MustParseTime(now, this.To)
}

func (this AuthAdmTimeRange) StringT(now time.Time) string {
	return time_helpers.TimeF(time_helpers.MustParseTime(now, this.From)) + " - " + time_helpers.TimeF(time_helpers.MustParseTime(now, this.To))
}

func (this AuthAdmTimeRange) Validate(db *aorm.DB) {
	ctx := core.ContextFromDB(db)
	var now = time.Now()
	this.validateTime(db, ctx, now, "From", this.From)
	this.validateTime(db, ctx, now, "To", this.To)
}

func (this AuthAdmTimeRange) validateTime(db *aorm.DB, ctx *core.Context, now time.Time, field, value string) {
	if _, err := time_helpers.ParseTime(now, value); err != nil {
		db.AddError(validations.NewError(this, field, fmt.Sprintf(ctx.Ts(ctx.ErrorTS(err), ctx.Ts(timeAttributesKey+field)))))
	}
}

type AuthAdmLoginDayRule struct {
	aorm.AuditedModel

	Enabled,
	Sun, Mon, Tue, Wed,
	Thu, Fri, Sat bool

	ProtectorID string `sql:"size:24;index"`

	Times []AuthAdmTimeRange `sql:"foreignkey:RuleID"`
}

func (this AuthAdmLoginDayRule) String() string {
	return this.ID.String()
}

func (this AuthAdmLoginDayRule) AcceptWeekday(day ...time.Weekday) bool {
	for _, day := range day {
		switch day {
		case time.Sunday:
			if !this.Sun {
				return false
			}
		case time.Monday:
			if !this.Mon {
				return false
			}
		case time.Tuesday:
			if !this.Tue {
				return false
			}
		case time.Wednesday:
			if !this.Wed {
				return false
			}
		case time.Thursday:
			if !this.Thu {
				return false
			}
		case time.Friday:
			if !this.Fri {
				return false
			}
		case time.Saturday:
			if !this.Sat {
				return false
			}
		}
	}
	return true
}

type AuthAdmProtector struct {
	aorm.AuditedSDModel
	fragment.FragmentedModel

	Name, Description string

	Enabled    bool
	AutoLogout bool
	IpRules    []AuthAdmLoginIpRule   `sql:"foreignkey:ProtectorID"`
	DayRules   []AuthAdmLoginDayRule  `sql:"foreignkey:ProtectorID"`
	Users      []AuthAdmUserProtector `sql:"foreignkey:ProtectorID"`
}

func (AuthAdmProtector) GetAormInlinePreloadFields() []string {
	return []string{"Name", "Description"}
}

func (p AuthAdmProtector) String() (s string) {
	s = p.Name
	return
}

type AuthAdmMail struct {
	aorm.AuditedModel

	Address string

	AutoUpdaterID string `sql:"size:24;index"`
}

type AuthAdmPasswordsAutoUpdater struct {
	aorm.AuditedSDModel
	fragment.FragmentedModel

	Name, Description string

	Enabled bool

	Sun, Mon, Tue, Wed,
	Thu, Fri, Sat bool

	Users        []AuthAdmUserPasswordsAutoUpdater `sql:"foreignkey:AutoUpdaterID"`
	Notificators []AuthAdmMail                     `sql:"foreignkey:AutoUpdaterID"`
}

func (this AuthAdmPasswordsAutoUpdater) Days() (days []time.Weekday) {
	if this.Sun {
		days = append(days, time.Sunday)
	}
	if this.Mon {
		days = append(days, time.Monday)
	}
	if this.Tue {
		days = append(days, time.Tuesday)
	}
	if this.Wed {
		days = append(days, time.Wednesday)
	}
	if this.Thu {
		days = append(days, time.Thursday)
	}
	if this.Fri {
		days = append(days, time.Friday)
	}
	if this.Sat {
		days = append(days, time.Saturday)
	}
	return
}

type AuthAdmUserPasswordsAutoUpdater struct {
	fragment.FragmentModel

	AutoUpdaterID bid.BID `sql:"index"`
	AutoUpdater   *AuthAdmPasswordsAutoUpdater

	User *user.User `sql:"foreignkey:ID"`
}

func (AuthAdmUserPasswordsAutoUpdater) GetAormInlinePreloadFields(scope *aorm.Scope) []string {
	if reflect.TypeOf(scope.Value).Elem() == userType {
		return []string{"*", "AutoUpdater"}
	}
	return []string{"*", "User"}
}

func (p AuthAdmUserPasswordsAutoUpdater) String() string {
	if p.User != nil {
		return p.User.String()
	}
	return "[no value]"
}
