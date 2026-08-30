package aws

import (

	"context"  //carries cancellation/deadline signals through function calls
	"errors"  //used to check/unwrap specific error types
	"fmt"  //string formatting and building error messages
	"time"  //used to record the timestamp of when validation happened

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/southwickio/deadkey/internal/models"

)

//Validate checks whether cred is still alive by calling sts:GetCallerIdentity
//
//Docs: docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
//
//Per AWS's own documentation: "No permissions are required to perform this
//operation... Permissions are not required because the same information is
//returned when access is denied." This makes GetCallerIdentity the correct
//zero-permission baseline check. Every AWS credential this provider discovers
//can be validated regardless of what else it can or can't do
//
//A successful call proves the credential is syntactically valid and has not
//been revoked. It does NOT prove the credential can access any actual AWS
//resource. GetCallerIdentity requires no permissions by design, so success here
//is not evidence of the key's broader access. Callers must not treat
//ValidationValid as "this key can do things," only as "this key is alive"
//
//Metadata required on cred: metaAccessKeyID must be set (see discovery.go).
//This provider does not carry the secret access key on the Credential struct
//itself; only what's needed to identify which key to check. The actual secret
//material is read fresh from its original source (currently: environment
//variables) at call time.
func (p *Provider) Validate(ctx context.Context, 
	cred models.Credential) (models.ValidationResult, error) {
	
	client, err := stsClientFor(ctx, cred)
	if err != nil {

		return models.ValidationResult{},
		fmt.Errorf("aws: building STS client: %w", err)

	}

	_, callErr := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	checkedAt := time.Now()

	if callErr == nil {

		return models.ValidationResult{
			Status:    models.ValidationValid,
			CheckedAt: checkedAt,

		}, nil

	}

	if isAuthFailure(callErr) {

		return models.ValidationResult{

			Status:      models.ValidationInvalid,
			CheckedAt:   checkedAt,
			ErrorDetail: callErr.Error(),
		
		}, nil

	}

	//Anything else (network failure, timeout, unrecognized error) means we
	//don't actually know whether the credential works. The check itself failed.
	//Per the Provider interface's contract, this is a Go error, not a
	//ValidationInvalid result
	return models.ValidationResult{},
	fmt.Errorf("aws: calling sts:GetCallerIdentity: %w", callErr)

}

//isAuthFailure recognizes the specific AWS error codes that mean "this
//credential is genuinely invalid/expired/revoked," as opposed to some other
//failure (network, throttling) that doesn't tell us anything about the
//credential itself. Recognized codes come from AWS's documented STS/IAM error
//responses and commonly observed error codes for expired/invalid long-term
//credentials (InvalidClientTokenId, ExpiredToken, SignatureDoesNotMatch)
func isAuthFailure(err error) bool {

	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {

		return false

	}
	switch apiErr.ErrorCode() {

	case "InvalidClientTokenId", 
	"ExpiredToken", 
	"SignatureDoesNotMatch", 
	"AccessDenied":
		return true
	default:
		return false

	}

}

//stsClientFor builds an STS client authenticated as cred specifically, not
//whatever credentials happen to be active in the environment. This matters
//because deadkey may validate several different discovered credentials in one
//scan. Each must be checked as itself, not as "whatever's currently
//configured"
func stsClientFor(ctx context.Context, 
	cred models.Credential) (*sts.Client, error) {

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

	return sts.NewFromConfig(cfg), nil

}