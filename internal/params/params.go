package params

import (
	"net/url"
	"strings"
)

// trackingParams are query parameters that exist purely for analytics and
// attribution. They never affect server-side behavior and are useless for
// security testing — removing them reduces noise without losing coverage.
var trackingParams = map[string]bool{
	// Google
	"utm_source":   true,
	"utm_medium":   true,
	"utm_campaign": true,
	"utm_term":     true,
	"utm_content":  true,
	"utm_id":       true,
	"gclid":        true,
	"gclsrc":       true,
	"dclid":        true,
	// Meta / Facebook
	"fbclid":          true,
	"fb_action_ids":   true,
	"fb_action_types": true,
	// Microsoft
	"msclkid": true,
	// Mailchimp
	"mc_cid": true,
	"mc_eid": true,
	// HubSpot
	"hsa_acc":       true,
	"hsa_cam":       true,
	"hsa_grp":       true,
	"hsa_ad":        true,
	"hsa_src":       true,
	"hsa_tgt":       true,
	"hsa_kw":        true,
	"hsa_mt":        true,
	"hsa_net":       true,
	"hsa_ver":       true,
	"hsctatracking": true,
	// Generic tracking
	"ref":       true,
	"source":    true,
	"medium":    true,
	"campaign":  true,
	"affiliate": true,
	"_ga":       true,
	"_gl":       true,
}

// structuralParams are params where the VALUE matters for fingerprinting —
// ?format=json and ?format=xml are different endpoints structurally.
// Everything else ignores the value in the fingerprint.
var structuralParams = map[string]bool{
	"format":  true,
	"version": true,
	"v":       true,
	"lang":    true,
	"locale":  true,
	"type":    true,
	"output":  true,
	"api":     true,
}

// IsTracking returns true if the param name is a known tracking parameter.
func IsTracking(name string) bool {
	return trackingParams[strings.ToLower(name)]
}

// IsStructural returns true if the param value should be included in the fingerprint.
func IsStructural(name string) bool {
	return structuralParams[strings.ToLower(name)]
}

// StripTracking removes tracking params from a URL and returns the cleaned URL string.
// If no tracking params are present, returns the original string unchanged.
func StripTracking(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	q := u.Query()
	dirty := false
	for k := range q {
		if trackingParams[strings.ToLower(k)] {
			delete(q, k)
			dirty = true
		}
	}
	if !dirty {
		return raw
	}

	u.RawQuery = q.Encode()
	return u.String()
}
