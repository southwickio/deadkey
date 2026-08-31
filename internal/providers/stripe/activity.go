package stripe

import (

	"context"  //carries cancellation/deadline signals through function calls

	"github.com/southwickio/deadkey/internal/models"

)

//GetActivity always returns ActivityUnavailable. This is a confirmed
//conclusion, not an assumption made without checking
//
//Stripe's Activity Logs API (docs.stripe.com/activity-logs) was researched
//specifically as a candidate inference source, since it looked promising by
//name. Its documented tracked action types are api_key_created,
//api_key_deleted, api_key_updated, and api_key_viewed. These are key MANAGEMENT
//events, not key USAGE events. There is novapi_key_used_for_request action type
//or equivalent. This means thevActivity Logs API cannot answer "was this key
//used recently to make APIvcalls," which is the question GetActivity needs to
//answer. Here, it can only answer "when was this key created, deleted,
//modified, or viewed in the Dashboard"
//
//No other confirmed API-based signal for key usage recency was found during
//research for this provider. This is a genuine, structural limitation of
//Stripe's API surface, not a gap in this implementation. See
//provider-requirements.md's Known Limitations section
//
//Team-member/2FA-style risk signals exist only via SCIM, which requires an
//Enterprise plan with SSO enabled
func (p *Provider) GetActivity(ctx context.Context,
	cred models.Credential) (models.ActivityResult, error) {

	return models.ActivityResult{

		Quality: models.ActivityUnavailable,
		Source: "Stripe's Activity Logs API tracks key management (created/deleted/updated/viewed), not key usage; no API-based last-used signal exists for any Stripe credential type",

	}, nil

}