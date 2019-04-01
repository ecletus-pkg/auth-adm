package authadm

import (
	admin_plugin "github.com/ecletus-pkg/admin"
	"github.com/ecletus-pkg/user"
	"github.com/ecletus/admin"
	"github.com/ecletus/db"
	"github.com/ecletus/helpers"
	"github.com/ecletus/plug"
)

type Plugin struct {
	plug.EventDispatcher
	db.DBNames
	admin_plugin.AdminNames

	CronKey,
	LogoutersKey string
}

func (p *Plugin) OnRegister(options *plug.Options) {
	if p.CronKey == "" {
		panic("CronKey is BLANK")
	}
	if p.LogoutersKey == "" {
		panic("LogoutersKey is BLANK")
	}

	admin_plugin.Events(p).InitResources(func(e *admin_plugin.AdminEvent) {
		Admin := e.Admin
		_ = Admin.OnResourceValueAdded(&user.Group{}, func(e *admin.ResourceEvent) {
			e.Resource.AddFragmentConfig(&AuthAdmProtector{}, &admin.FragmentConfig{
				Is: true,
				Config: &admin.Config{
					Setup: setupProtector,
				},
			})
			e.Resource.AddFragmentConfig(&AuthAdmPasswordsAutoUpdater{}, &admin.FragmentConfig{
				Is: true,
				Config: &admin.Config{
					Setup: setupPasswordsUpdater,
				},
			})
		})
	})

	db.Events(p).DBOnMigrate(func(e *db.DBEvent) error {
		return helpers.CheckReturnE(func() (key string, err error) {
			return "Migrate", e.AutoMigrate(
				&AuthAdmMail{},
				&AuthAdmLoginDayRule{},
				&AuthAdmLoginIpRule{},
				&AuthAdmPasswordsAutoUpdater{},
				&AuthAdmProtector{},
				&AuthAdmTime{},
				&AuthAdmTimeRange{},
			).Error
		})
	})
}
