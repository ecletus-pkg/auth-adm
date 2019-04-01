package authadm

import "github.com/ecletus/admin"

func setupProtector(Admin *admin.Admin, res *admin.Resource) {
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
			res.NIESAttrs("Enabled", [][]string{{"From", "To"}})
		})
		res.NIESAttrs(&admin.Section{Rows: [][]string{
			{"Enabled"},
			{"Sun", "Mon", "Tue"},
			{"Wed", "Thu", "Fri"},
			{"Sat"},
		}}, "Times")
	})
}
