package authadm

import (
	"fmt"
	"github.com/ecletus/admin"
	"github.com/ecletus/admin/admin_helpers"
	"github.com/ecletus/core"
)

func setupProtector(res *admin.Resource) {
	scheme := res.Fragment.Scheme()
	scheme.IndexAttrs("Group", "Description", "AutoLogout")
	res.ShowAttrs(res.EditAttrs())

	res.AddResourceField("IpRules", nil, func(res *admin.Resource) {
		res.NIESAttrs(&admin.Section{Rows: [][]string{
			{"Enabled", "Ip"},
		}}, "Times")
	})
	res.AddResourceField("DayRules", nil, func(res *admin.Resource) {
		res.AddResourceField("Times", nil, func(res *admin.Resource) {
			res.Meta(&admin.Meta{Name: "From", Type: "time"})
			res.Meta(&admin.Meta{Name: "To", Type: "time"})
			res.NIESAttrs([][]string{{"Enabled", "From", "To"}})
		})
		res.NIESAttrs(&admin.Section{Rows: [][]string{
			{"Enabled"},
			{"Sun", "Mon", "Tue"},
			{"Wed", "Thu", "Fri"},
			{"Sat"},
		}}, "Times")
	})
}

func setupPasswordsUpdater(res *admin.Resource) {
	scheme := res.Fragment.Scheme()

	scheme.IndexAttrs("Group", "Sun", "Mon", "Tue",
		"Wed", "Thu", "Fri", "Sat", "AutoLogout")

	res.EditAttrs(&admin.Section{Rows: [][]string{
		{"Enabled"},
		{"Sun", "Mon", "Tue"},
		{"Wed", "Thu", "Fri"},
		{"Sat"},
	}}, "Times", "Notificators")
	res.ShowAttrs(res.EditAttrs())

	res.AddResourceField("Times", nil, func(res *admin.Resource) {
		res.Meta(&admin.Meta{Name:"Hour", Config:&admin.SelectOneConfig{Collection:admin_helpers.CollectionIntRange(0, 23, 1)}})
		res.Meta(&admin.Meta{Name:"Minute", Config:&admin.SelectOneConfig{Collection:admin_helpers.CollectionIntRange(0, 59, 1)}})
		res.Meta(&admin.Meta{Name:"Second", Config:&admin.SelectOneConfig{Collection:admin_helpers.CollectionIntRange(0, 59, 1)}})
		res.Meta(&admin.Meta{Name: "Time", Valuer: func(recorde interface{}, context *core.Context) interface{} {
			t := recorde.(*AuthAdmTime)
			return fmt.Sprintf("%02d:%02d:%02dH", t.Hour, t.Minute, t.Second)
		}})
		res.EditAttrs([][]string{{"Hour", "Minute", "Second"}})
		res.NewAttrs([][]string{{"Hour", "Minute", "Second"}})
		res.ShowAttrs("Time")
		res.IndexAttrs("Time")
	})

	res.AddResourceField("Notificators", nil, func(res *admin.Resource) {
		res.NIESAttrs("Address")
	})
}
