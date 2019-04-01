package authadm

import (
	"github.com/ecletus-pkg/admin"
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
					Setup: func(res *admin.Resource) {
						setupProtector(Admin, res)
					},
				},
			})
		})
	})

	db.Events(p).DBOnMigrate(func(e *db.DBEvent) error {
		return helpers.CheckReturnE(func() (key string, err error) {
			return "Migrate", e.AutoMigrate(&AuthAdmDayRule{}, &AuthAdmIpRule{}, &AuthAdmProtector{}, &AuthAdmTimeRange{}).Error
		})
	})
}
