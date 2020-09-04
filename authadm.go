package authadm

import (
	"net/mail"

	"github.com/ecletus/roles"

	"github.com/ecletus/auth/claims"

	"github.com/ecletus/mailer"

	admin_plugin "github.com/ecletus-pkg/admin"
	"github.com/ecletus/admin"
	"github.com/ecletus/auth"
	"github.com/ecletus/core"
	"github.com/ecletus/db"
	"github.com/ecletus/helpers"
	"github.com/ecletus/plug"
	"github.com/moisespsena-go/i18n-modular/i18nmod"
	path_helpers "github.com/moisespsena-go/path-helpers"
	"github.com/op/go-logging"
	"github.com/robfig/cron"
	passwordGen "github.com/sethvargo/go-password/password"
)

var (
	pkg    = path_helpers.GetCalledDir()
	group  = i18nmod.PkgToGroup(pkg)
	log    = logging.MustGetLogger(pkg)
	logpwd = logging.MustGetLogger(pkg + "@passwords-update")
)

type Plugin struct {
	plug.EventDispatcher
	db.DBNames
	admin_plugin.AdminNames

	CronKey,
	AuthKey,
	LogoutersKey,
	SitesRegisterKey,
	TranslatorKey,
	MailerKey string

	resProtector,
	resPasswordUpdater *admin.Resource
}

func (p *Plugin) RequireOptions() []string {
	return []string{p.AuthKey, p.CronKey, p.LogoutersKey, p.SitesRegisterKey,
		p.TranslatorKey, p.MailerKey}
}

func (p *Plugin) OnRegister(options *plug.Options) {
	if p.CronKey == "" {
		panic("CronKey is BLANK")
	}
	if p.LogoutersKey == "" {
		panic("LogoutersKey is BLANK")
	}
	if p.AuthKey == "" {
		panic("AuthKey is BLANK")
	}

	admin_plugin.Events(p).InitResources(func(e *admin_plugin.AdminEvent) {
		Admin := e.Admin
		p.resProtector = Admin.AddResource(&AuthAdmProtector{}, &admin.Config{
			Setup:      setupProtector,
			Permission: roles.AllowAny(admin.ROLE),
		})

		p.resPasswordUpdater = Admin.AddResource(&AuthAdmPasswordsAutoUpdater{}, &admin.Config{
			Setup:      setupPasswordsUpdater,
			Permission: roles.AllowAny(admin.ROLE),
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
				&AuthAdmTimeRange{},
				&AuthAdmUserProtector{},
				&AuthAdmUserPasswordsAutoUpdater{},
			).Error
		})
	})
}

func (p *Plugin) Init(options *plug.Options) {
	Auth := options.GetInterface(p.AuthKey).(*auth.Auth)
	Auth.LoginCallbacks.Logged(func(ctx *auth.LoginContext, Claims *claims.Claims) (err error) {
		if Claims.IsAdmin {
			return
		}
		return Validate(ctx.Context.Context, Claims.UserID, Claims)
	})

	Cron := options.GetInterface(p.CronKey).(*cron.Cron)
	err := Cron.AddFunc("@daily", func() {
		var (
			sitesRegister = options.GetInterface(p.SitesRegisterKey).(*core.SitesRegister)
			translator    = options.GetInterface(p.TranslatorKey).(*i18nmod.Translator)
		)
		pu := PasswordUpdater{
			SitesRegister: sitesRegister,
			Translator:    translator,
			Auth:          Auth,
		}
		pu.Update()
	})
	if err != nil {
		println(err)
	}
}

func genPwd() (pwd string, err error) {
	var g *passwordGen.Generator
	g, err = passwordGen.NewGenerator(&passwordGen.GeneratorInput{
		Symbols: "!@#$%&*()-+={[}]/:;.,!",
	})
	if err != nil {
		return
	}
	for i := 0; i < 3; i++ {
		pwd, err = g.Generate(10, 3, 2, false, false)
		if err == nil {
			return pwd, nil
		}
	}
	return
}

type NewUserPassword struct {
	Name, Email, Password string
}

func notify(Mailer *mailer.Mailer, context *core.Context, notificators []AuthAdmMail, passwords []NewUserPassword) (err error) {
	var to []mail.Address
	for _, n := range notificators {
		to = append(to, mail.Address{Address: n.Address})
	}

	return Mailer.Send(
		context.Site,
		mailer.Email{
			TO:      to,
			Subject: context.Ts(group + ".passwords_updated"),
			Lang:    context.GetI18nContext().Locales(),
		}, mailer.Template{
			Name: "auth-adm/password-updater/passwords-updated",
			Data: &struct {
				*core.Context
				Result interface{}
			}{context, passwords},
			Context: context,
		},
	)
}
