package detect

import (
	"net/url"
	"strings"
)

// Tech detection only matches against the path — never query values.
// Weak signals like "/api/" or ".js" are intentionally excluded.
// Better to return "" than fire on something generic.

type sig struct {
	needle string
	tech   string
}

var sigs = []sig{
	{"/actuator", "spring"},
	{".action", "struts"},
	{".do", "struts"},
	{"/wp-admin", "wordpress"},
	{"/wp-content", "wordpress"},
	{"/wp-json", "wordpress"},
	{"/xmlrpc.php", "wordpress"},
	{"/administrator", "joomla"},
	{"/components/com_", "joomla"},
	{"/sites/default", "drupal"},
	{"/_debugbar", "laravel"},
	{"/telescope", "laravel"},
	{"/horizon", "laravel"},
	{".cfm", "coldfusion"},
	{".cfc", "coldfusion"},
	{".jsp", "java"},
	{".jsf", "java"},
	{"/servlet/", "java"},
	{".aspx", "dotnet"},
	{".ashx", "dotnet"},
	{".asmx", "dotnet"},
	{"/graphql", "graphql"},
	{".php", "php"},
}

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Identify(u *url.URL) string {
	p := strings.ToLower(u.Path)
	for _, s := range sigs {
		if strings.Contains(p, s.needle) {
			return s.tech
		}
	}
	return ""
}
