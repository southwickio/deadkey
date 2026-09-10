//Package telemetry sends anonymous, opt-in risk-feedback events. This package
//is deliberately just the sending mechanism - it has no opinion about WHEN
//feedback should be sent. See models.FeedbackPayload for exactly what is and
//isn't included in what gets sent
package telemetry

import (

	"bytes"  //building the JSON request body
	"context"  //carries cancellation/deadline signals
	"encoding/json"  //encoding the payload
	"fmt"  //building error messages
	"net/http"  //making the request
	"os"  //reading the endpoint from the environment

	"github.com/southwickio/deadkey/internal/models"

)

//endpointEnvVar is where the ingest endpoint's URL is configured. This is
//deliberately an env var with no hardcoded default, rather than a placeholder
//URL that would simply fail every single call. An unset endpoint means
//telemetry is sent to nowhere, safely and predictably
const endpointEnvVar = "DEADKEY_TELEMETRY_ENDPOINT"

//SendFeedback POSTs payload as JSON to the configured ingest endpoint
//
//This endpoint is deliberately unauthenticated. No API key or bearer token is
//attached. Abuse protection is the server's responsibility, not something this
//client needs to participate in
//
//No retry logic: a single missed anonymous feedback event isn't worth the
//complexity of a retry/backoff scheme. Callers should treat a returned error as
//safely ignorable for this reason. Sending feedback is never important enough
//to justify surfacing a failure to the person running deadkey, or to
//delay/block whatever triggered the send. This function returns a normal Go
//error rather than swallowing failures itself, consistent with every other
//outbound call in this project. It is the CALLER's responsibility to decide a
//telemetry failure doesn't matter, not this function's job to hide that
//decision
//
//Returns nil immediately, without attempting any network call, if
//endpointEnvVar isn't set. This is the expected, common case until a real
//ingest endpoint exists and someone configures deadkey to use it. Not a
//degraded state worth logging or erroring about
func SendFeedback(ctx context.Context, payload models.FeedbackPayload) error {

	endpoint := os.Getenv(endpointEnvVar)
	if endpoint == "" {

		return nil

	}

	body, err := json.Marshal(payload)
	if err != nil {

		return fmt.Errorf("telemetry: encoding feedback payload: %w", err)

	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {

		return fmt.Errorf("telemetry: building request: %w", err)

	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return fmt.Errorf("telemetry: sending feedback to %s: %w", endpoint, err)

	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {

		return fmt.Errorf("telemetry: ingest endpoint returned HTTP %d", resp.StatusCode)

	}

	return nil

}