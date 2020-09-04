package authadm

import (
	"net"
	"time"

	"github.com/moisespsena-go/middleware"

	siteconf_location "github.com/ecletus-pkg/siteconf-location"

	"github.com/ecletus/auth/claims"

	"github.com/ecletus/core"
	"github.com/moisespsena-go/aorm"
	"github.com/pkg/errors"
)

func Validate(ctx *core.Context, userId string, Claims *claims.Claims) (err error) {
	var protectorId string

	var deny = func() (err error) {
		return errors.New(ctx.Ts(group + ".err_deny"))
	}

	DB := ctx.db
	if err = DB.
		Model(&AuthAdmProtector{}).
		Joins("JOIN auth_adm_user_protectors u ON u.protector_id = auth_adm_protectors.id").
		Where("u.id = ? AND auth_adm_protectors.enabled", userId).
		PluckFirst("auth_adm_protectors.id", &protectorId).Error; err != nil || protectorId == "" {
		if aorm.IsRecordNotFoundError(err) {
			if err = DB.
				Model(&AuthAdmProtector{}).
				Where("auth_adm_protectors.enabled AND NOT EXISTS ("+
					"SELECT 1 FROM auth_adm_user_protectors u WHERE u.protector_id = auth_adm_protectors.id"+
					")").
				PluckFirst("auth_adm_protectors.id", &protectorId).Error; err != nil || protectorId == "" {
				if aorm.IsRecordNotFoundError(err) {
					return nil
				} else {
					return
				}
			}
		} else {
			return
		}
	}

	var (
		ipRules  []AuthAdmLoginIpRule
		dayRules []AuthAdmLoginDayRule
	)

	if err = DB.
		Where("protector_id = ? AND enabled", protectorId).
		Find(&ipRules).
		Error; err != nil && !aorm.IsRecordNotFoundError(err) {
		return
	}

	if len(ipRules) > 0 {
		var (
			match      bool
			clientAddr = net.ParseIP(middleware.GetRealIP(ctx.Request))
		)
		for _, rule := range ipRules {
			if match = rule.Ip.MustRange().Contains(clientAddr); match {
				break
			}
		}
		if !match {
			return deny()
		}
	}

	if err = DB.
		Where("protector_id = ? AND enabled", protectorId).
		Find(&dayRules).
		Error; err != nil {
		if !aorm.IsRecordNotFoundError(err) {
			return
		}
		err = nil
	}

	var (
		loc = siteconf_location.GetOrSysC(ctx)
		now = time.Now().In(loc.Location())
	)

	if len(dayRules) > 0 {
		var match bool

		for _, rule := range dayRules {
			var times []AuthAdmTimeRange
			if err = DB.
				Where("rule_id = ?", rule.ID).
				Find(&times).
				Error; err != nil && !aorm.IsRecordNotFoundError(err) {
				return
			}

			if rule.AcceptWeekday(now.Weekday()) {
				if len(times) == 0 {
					Claims.ExpiresAt = time.Date(now.Year(), now.Month(), now.Day(),
						0, 0, 0, 0, now.Location()).
						Add(time.Hour * 24).
						Unix()
					match = true
					break
				}

				for _, rule := range times {
					From, To := rule.Times(now)
					if From.Before(now) && To.After(now) {
						Claims.ExpiresAt = To.Unix()
						match = true
						break
					}
				}

				break
			}
		}

		if !match {
			return deny()
		}
	}

	return
}
