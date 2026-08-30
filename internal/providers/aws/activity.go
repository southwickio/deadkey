package aws

import (

	"context"  //carries cancellation/deadline signals through function calls
	"errors"  //used to check/unwrap specific error types
	"fmt"  //string formatting and building error messages

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"github.com/southwickio/deadkey/internal/models"

)

//GetActivity reports how "alive" cred looks by calling iam:GetAccessKeyLastUsed
//
//Docs: docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html
//
//Required permission: iam:GetAccessKeyLastUsed on the key itself
//
//Per AWS's documentation, LastUsedDate is null/absent specifically when: "An
//access key exists but has not been used since IAM began tracking this
//information" (since April 22, 2015). This is reported as ActivityConfirmed
//with LastUsedAt left nil, never as ActivityUnavailable. Conflating "confirmed
//never used" with "we don't know" would throw away real information this API
//provides
//
//If the call itself fails because the scanning credential lacks
//iam:GetAccessKeyLastUsed permission (a normal, expected situation per the
// permission-tiering principle of this project), this returns
//ActivityUnavailable, not a Go error. A Go error is reserved for failures that
//mean the check couldn't be attempted at all (network failure, unrecognized
//error). A recognized permissions denial is an informative result, not a broken
//operation
func (p *Provider) GetActivity(ctx context.Context, 
	cred models.Credential) (models.ActivityResult, error) {

	client, err := iamClientFor(ctx, cred)
	if err != nil {

		return models.ActivityResult{}, 
		fmt.Errorf("aws: building IAM client: %w", err)

	}

	accessKeyID := cred.Metadata[metaAccessKeyID]

	out, callErr := client.GetAccessKeyLastUsed(ctx, 
		&iam.GetAccessKeyLastUsedInput{

		AccessKeyId: &accessKeyID,

	})

	if callErr != nil {

		if isPermissionDenied(callErr) {

			return models.ActivityResult{

				Quality: models.ActivityUnavailable,
				Source: "iam:GetAccessKeyLastUsed denied (insufficient permissions on scanning credential)",

			}, nil

		}
		return models.ActivityResult{}, 
		fmt.Errorf("aws: calling iam:GetAccessKeyLastUsed: %w", callErr)

	}

	result := models.ActivityResult{

		Quality: models.ActivityConfirmed,
		Source: "iam:GetAccessKeyLastUsed",

	}

	if out.AccessKeyLastUsed != nil && out.AccessKeyLastUsed.LastUsedDate != nil {

		result.LastUsedAt = out.AccessKeyLastUsed.LastUsedDate

	}

	//If LastUsedDate is nil, result.LastUsedAt stays nil too. This is the
	//"confirmed never used" case described above. Quality remains
	//ActivityConfirmed; we are not missing data, we know the answer
	return result, nil

}

//isPermissionDenied recognizes AWS's standard access-denied error code. Used
//here (and in risk_modifiers.go) to distinguish "the scanning credential
//isn't allowed to run this check". Expected, degrades gracefully, from a
//genuine unexpected failure
func isPermissionDenied(err error) bool {

	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {

		return false

	}
	return apiErr.ErrorCode() == "AccessDenied" || apiErr.ErrorCode() == "AccessDeniedException"
}

//iamClientFor mirrors stsClientFor (validate.go) but builds an IAM client.
//Secret resolution is shared via resolveSecretAccessKey (secret.go)
func iamClientFor(ctx context.Context, 
	cred models.Credential) (*iam.Client, error) {

	accessKeyID, ok := cred.Metadata[metaAccessKeyID]
	if !ok || accessKeyID == "" {

		return nil,
		fmt.Errorf("credential missing %s in Metadata", metaAccessKeyID)

	}

	secretKey, err := resolveSecretAccessKey(cred)
	if err != nil {

		return nil, err

	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, ""),
			
		),

	)
	if err != nil {

		return nil, err

	}

	return iam.NewFromConfig(cfg), nil

}