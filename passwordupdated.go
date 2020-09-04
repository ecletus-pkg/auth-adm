package authadm

import (
	"fmt"
	"sync"

	"github.com/ecletus-pkg/user"
	"github.com/ecletus/auth"
	"github.com/ecletus/core"
	"github.com/ecletus/mailer"
	"github.com/moisespsena-go/i18n-modular/i18nmod"
)

type PasswordUpdater struct {
	SitesRegister *core.SitesRegister
	Translator    *i18nmod.Translator
	Auth          *auth.Auth
	mu            sync.Mutex
	running       bool
}

func (this PasswordUpdater) Update() {
	if this.running {
		return
	}
	this.mu.Lock()
	defer this.mu.Unlock()
	if this.running {
		return
	}
	this.running = true

	var (
		tContext = this.Translator.NewContext("pt-BR")

		T = func(key string, defaul ...interface{}) string {
			t := tContext.T(key)
			if len(defaul) > 0 {
				t = t.Default(defaul[0])
			}
			return t.Get()
		}
		names = this.SitesRegister.ByName.Names()
	)
	for _, name := range names {
		if site, ok := this.SitesRegister.Get(name); ok {
			context := site.NewContext()
			context.Translator = this.Translator
			context.Locale = "pt-BR"
			DB := site.GetSystemDB().DB
			msg := "{" + site.Name() + "} "

			var updaters []AuthAdmPasswordsAutoUpdater
			if err := DB.Find(&updaters, "enabled").Error; err != nil {
				log.Info(msg+"load updaters failed:", err.Error())
				continue
			}

			for _, up := range updaters {
				var (
					notificators []AuthAdmMail
					users        []AuthAdmUserPasswordsAutoUpdater
					passwords    []NewUserPassword
				)

				if err := DB.Find(&notificators, "auto_updater_id = ?", up.ID).Error; err != nil {
					log.Error(msg+"load notificators failed:", err.Error())
					continue
				}

				if len(notificators) == 0 {
					log.Warning("no have notificatores. Canceled.")
					continue
				}

				if err := DB.Find(&users, "auto_updater_id = ?", up.ID).Error; err != nil {
					log.Error(msg+"load users failed:", err.Error())
					continue
				}

				for _, User := range users {
					msg := msg + fmt.Sprintf("{#%s %s} ", User.ID, User.User.Email)
					logpwd.Info(msg + "start")
					pwd, err := genPwd()
					if err != nil {
						logpwd.Errorf(msg+"generate failed: %s", err)
						continue
					}
					if err = user.SetUserPassword(site, DB, this.Auth, nil, User.User, pwd, T); err != nil {
						logpwd.Errorf(msg+"save failed: %s", err)
						continue
					}
					logpwd.Info(msg + "new password: " + pwd)
					passwords = append(passwords, NewUserPassword{
						User.User.Name,
						User.User.Email,
						pwd,
					})
				}

				if err := notify(mailer.MustGet(site.Data), context, notificators, passwords); err != nil {
					log.Error(msg+"notify failed:", err.Error())
					continue
				}
			}
		}
	}
}
