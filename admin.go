package authadm

import (
	"strings"

	"github.com/ecletus/admin"
	"github.com/ecletus/admin/admin_helpers"
	"github.com/ecletus/core"
)

func setupProtector(res *admin.Resource) {
	res.IndexAttrs("Name", "Description", "AutoLogout", "Enabled")
	res.ShowAttrs(res.EditAttrs())
	res.SearchAttrs("Name")
	res.NewAttrs("Name", "Description")
	res.DefaultMenu().MdlIcon = "vpn_key"

	res.AddResourceField("Users", nil, func(res *admin.Resource) {
		res.INESAttrs("User")
		admin_helpers.SelectOneOption(admin_helpers.SelectConfigOptionBottonSheet, res, "User")
	})

	res.AddResourceField("IpRules", nil, func(res *admin.Resource) {
		res.INESAttrs(&admin.Section{Rows: [][]string{
			{"Enabled", "Ip"},
		}}, "Times")
	})
	res.AddResourceField("DayRules", nil, func(res *admin.Resource) {
		res.AddResourceField("Times", nil, func(res *admin.Resource) {
			res.INESAttrs([][]string{{"From", "To"}})
		})
		res.INESAttrs(&admin.Section{Rows: [][]string{
			{"Enabled"},
			{"Sun", "Mon", "Tue"},
			{"Wed", "Thu", "Fri"},
			{"Sat"},
		}}, "Times")
	})
}

func setupPasswordsUpdater(res *admin.Resource) {
	res.IndexAttrs("Name", "Description", "Days", "Enabled")
	res.Meta(&admin.Meta{
		Name: "Days",
		Valuer: func(recorde interface{}, context *core.Context) interface{} {
			var days []string
			for _, day := range recorde.(*AuthAdmPasswordsAutoUpdater).Days() {
				days = append(days, context.Ts(res.I18nPrefix+".attributes."+day.String()[0:3]))
			}
			return strings.Join(days, ", ")
		},
	})
	res.NewAttrs(&admin.Section{Rows: [][]string{
		{"Enabled"},
		{"Sun", "Mon", "Tue"},
		{"Wed", "Thu", "Fri"},
		{"Sat"},
	}}, "Notificators")
	res.EditAttrs(res.NewAttrs())
	res.ShowAttrs("Name", "Description", "Enabled", "Days", "Users")

	res.AddResourceField("Notificators", nil, func(res *admin.Resource) {
		res.INESAttrs("Address")
	})

	res.AddResourceField("Users", nil, func(res *admin.Resource) {
		res.INESAttrs("User")
		admin_helpers.SelectOneOption(admin_helpers.SelectConfigOptionBottonSheet, res, "User")
	})
}