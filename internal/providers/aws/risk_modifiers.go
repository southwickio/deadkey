package aws

import (
	"context"  //carries cancellation/deadline signals through function calls
	"encoding/json"  //parsing the inline policy document's JSON content
	"net/url"  //decoding the URL-encoded policy document AWS returns

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/southwickio/deadkey/internal/models"
)

//Stable RiskModifier codes for this provider. Per risk.go's doc comment, these
//must never be renamed once shipped. They are the join key for any future
//telemetry-driven analysis of modifier accuracy
const (

	modifierCodeAdminPolicy = "aws_admin_policy"
	modifierCodeNoMFA       = "aws_no_mfa"

)

//adminPolicyName is AWS's own managed policy for full administrator access.
//Checking for it by name is a reliable, exact match for MANAGED policies. AWS's
//managed policy names are fixed and can't be renamed by the customer. This does
//NOT apply to inline policies, which can be named anything regardless of what
//they actually grant. See hasAdminPolicy for how those are handled differently,
//by content rather than by name
const adminPolicyName = "AdministratorAccess"

//RiskModifiers implements the optional providers.RiskModifierProvider interface
//(see provider.go). It runs two independent checks against the IAM user that
//owns cred's access key:
//  1. Does the user have admin-equivalent access, via either a managed policy
//     (checked by name) or an inline policy (checked by actually parsing its
//     policy document. See hasAdminPolicy)?
//     Docs: docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedUserPolicies.html
//     Docs: docs.aws.amazon.com/IAM/latest/APIReference/API_GetUserPolicy.html
//     Required permissions: 
// 	     - iam:ListAttachedUserPolicies
//       - iam:ListUserPolicies
//       - iam:GetUserPolicy
//  2. Does the user have no MFA device enrolled?
//     Docs: docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_checking-status.html
//     Required permission: iam:ListMFADevices
//Both checks require permissions beyond what Validate/GetActivity need. Per the
//permission-tiering principle of this project: if the scanning credential lacks
//permission for either check, that check's modifier is simply omitted from the
//returned list. It is never a Go error; never a crash
//
//Both checks are performed on the IAM user, not the access key itself. AWS
//attaches policies and MFA devices to users, not to individual keys. A user
//with multiple access keys will get the same modifiers for each of their keys,
//which is correct: the risk (admin access, no MFA) applies to anything that key
//can do, regardless of which specific key is being evaluated
func (p *Provider) RiskModifiers(ctx context.Context, 
	cred models.Credential) ([]models.RiskModifier, error) {

	client, err := iamClientFor(ctx, cred)

	if err != nil {

		//Building the client itself failing (for example: no secret key
		//available) is a real error. This is different from a permissions
		//denial on a specific call, which is handled per-check below
		return nil, err

	}

	userName, err := currentUserName(ctx, client)
	if err != nil {

		if isPermissionDenied(err) {

			//Can't even determine the username to check. No modifiers
			//available. Not an error.
			return nil, nil

		}
		return nil, err

	}

	var modifiers []models.RiskModifier

	if hasAdminPolicy(ctx, client, userName) {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeAdminPolicy,
			Adjustment: 30,
			Reason: "IAM user has admin-equivalent access (managed or inline policy)",
			Confidence: 0.9,

		})

	}

	if hasNoMFA(ctx, client, userName) {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeNoMFA,
			Adjustment: 15,
			Reason: "IAM user has no MFA device enrolled",
			Confidence: 0.9,

		})

	}

	return modifiers, nil
}

//currentUserName resolves the IAM username that owns cred's access key, via
//iam:GetUser (no username argument -> "the user making this call")
//Docs: docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html
func currentUserName(ctx context.Context, 
	client *iam.Client) (string, error) {

	out, err := client.GetUser(ctx, &iam.GetUserInput{})
	if err != nil {

		return "", err

	}
	return *out.User.UserName, nil

}

//hasAdminPolicy checks both managed (attached) and inline policies, since an
//IAM user can have admin-equivalent access via either. Checking only one would
//systematically miss the other
//
//Managed policies are checked by name (adminPolicyName); reliable, since AWS's
//own managed policy names are fixed
//
//Inline policies are checked by CONTENT, not name. An inline policy can be
//named anything regardless of what it actually grants, so a name-based check
//would miss a genuinely admin-equivalent inline policy with an unrelated name.
//Each inline policy's document is fetched (iam:GetUserPolicy) and parsed as
//JSON; a statement with Effect "Allow", Action "*" (or including "*"), and
//Resource "*" (or including "*") is treated as admin-equivalent, matching how
//AWS's own AdministratorAccess managed policy is itself defined
//
//Any failure (including permission denial, or a policy document that doesn't
//parse as expected) is treated as "couldn't determine, don't flag". This check
//must never produce a false positive from an incomplete or malformed read, and
//a missing modifier is a safer failure mode than an incorrect one
func hasAdminPolicy(ctx context.Context, 
	client *iam.Client, 
	userName string) bool {

	attached, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{

		UserName: &userName,

	})
	if err == nil {

		for _, policy := range attached.AttachedPolicies {

			if policy.PolicyName != nil && *policy.PolicyName == adminPolicyName {

				return true

			}

		}

	}

	inline, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{

		UserName: &userName,

	})
	if err != nil {

		return false

	}

	for _, policyName := range inline.PolicyNames {

		policyNameCopy := policyName
		doc, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{

			UserName:   &userName,
			PolicyName: &policyNameCopy,

		})
		if err != nil {

			//Can't read this specific policy's content. Skip it rather than
			//guessing. Other inline policies are still checked below
			continue

		}
		if doc.PolicyDocument == nil {

			continue

		}
		if policyDocumentGrantsAdmin(*doc.PolicyDocument) {

			return true

		}

	}

	return false

}

//iamPolicyDocument mirrors the small subset of AWS's IAM policy JSON structure
//this check actually needs. AWS policy documents can express Action/Resource as
//either a single string or an array of strings, hence the custom UnmarshalJSON
//below to accept both shapes
type iamPolicyDocument struct {

	Statement []iamPolicyStatement `json:"Statement"`

}

type iamPolicyStatement struct {

	Effect   string            `json:"Effect"`
	Action   flexibleStringSet `json:"Action"`
	Resource flexibleStringSet `json:"Resource"`

}

//flexibleStringSet unmarshals an IAM policy field that AWS allows to be either
//a single JSON string or an array of strings, into a single consistent []string
//regardless of which shape was actually used
type flexibleStringSet []string

func (f *flexibleStringSet) UnmarshalJSON(data []byte) error {

	var single string
	if err := json.Unmarshal(data, &single); err == nil {

		*f = []string{single}
		return nil

	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {

		return err

	}
	*f = multiple
	return nil

}

func (f flexibleStringSet) contains(target string) bool {

	for _, v := range f {

		if v == target {

			return true

		}

	}
	return false

}

//policyDocumentGrantsAdmin parses a raw IAM policy document (as returned by
//GetUserPolicy; URL-encoded JSON) and reports whether any statement in it
//grants blanket admin-equivalent access: Effect "Allow", Action including "*",
//Resource including "*". This mirrors the actual content of AWS's own
//AdministratorAccess managed policy, rather than guessing based on a name
//
//A document that fails to decode or parse is treated as "not admin" (false),
//not as an error; per hasAdminPolicy's doc comment, an unreadable or unexpected
//document shape must not produce a false positive
func policyDocumentGrantsAdmin(rawDocument string) bool {

	decoded, err := url.QueryUnescape(rawDocument)
	if err != nil {

		return false

	}

	var doc iamPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {

		return false

	}

	for _, stmt := range doc.Statement {

		if stmt.Effect != "Allow" {

			continue

		}
		if stmt.Action.contains("*") && stmt.Resource.contains("*") {

			return true

		}

	}
	return false

}

//hasNoMFA returns true if the user has zero MFA devices enrolled. Any failure
//(including permission denial) returns false; same safer-to-under-flag
//reasoning as hasAdminPolicy
func hasNoMFA(ctx context.Context, client *iam.Client, userName string) bool {

	out, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{

		UserName: &userName,

	})
	if err != nil {

		return false

	}
	return len(out.MFADevices) == 0

}