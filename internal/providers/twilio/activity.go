package twilio

import (

	"context"  //carries cancellation/deadline signals through function calls

	"github.com/southwickio/deadkey/internal/models"

)

//GetActivity always returns ActivityUnavailable. This is a confirmed,
//researched conclusion, not a default:
//  - The Key resource (both v2010 and v1) exposes only dateCreated/dateUpdated;
//    no last-used field, confirmed against two independently generated SDKs
//    built from the same OpenAPI spec (twilio-ruby, twilio_elixir). dateUpdated
//    itself is a weaker signal than it first appears: it changes on a
//    Restricted key's permission edit or a rename, not only on use or rotation
//  - Auth Tokens have no per-token resource to query for activity
//  - Twilio's Monitor Events API (twilio.com/docs/usage/monitor-events) is
//    the closest thing to an enhanced/Mode-2-style activity signal (13 months
//    of retention on paid Editions, 30 days free), but its actor_sid/actor_type
//    fields collapse to the ACCOUNT (actor_type: "account", actor_sid:
//    the Account SID) for any API-authenticated request, regardless of which
//    specific API Key made the call
//
//Capabilities() (twilio.go) reports MaxActivityQuality as ActivityUnavailable
//accordingly, so the risk-scoring engine never treats this absence of data as
//evidence of inactivity
func (p *Provider) GetActivity(ctx context.Context,
	cred models.Credential) (models.ActivityResult, error) {

	return models.ActivityResult{

		LastUsedAt: nil,
		Quality:    models.ActivityUnavailable,
		Source:     "twilio: no per-credential last-used data exists in Twilio's API at any permission tier; see activity.go",

	}, nil

}
