//Package registry is the single place every deadkey provider is registered.
//Deliberately its own package, separate from internal/providers itself:
//internal/providers/aws (and every other provider package) already imports
//internal/providers for the shared Provider interface and ProviderCapabilities
//type, so internal/providers importing back down into internal/providers/aws
//would be a circular import. Sitting one level above both avoids that entirely
package registry

import (

	"fmt"  //building an error message for an unknown provider name
	"strings"  //joining known provider names into that error message

	"github.com/southwickio/deadkey/internal/providers"
	"github.com/southwickio/deadkey/internal/providers/aws"
	"github.com/southwickio/deadkey/internal/providers/github"
	"github.com/southwickio/deadkey/internal/providers/sendgrid"
	"github.com/southwickio/deadkey/internal/providers/stripe"
	"github.com/southwickio/deadkey/internal/providers/twilio"

)

//All returns every registered provider, in a fixed, stable order, so scan
//output is predictable across runs regardless of map iteration or similar
//nondeterminism
func All() []providers.Provider {

	return []providers.Provider{

		aws.New(),
		github.New(),
		sendgrid.New(),
		stripe.New(),
		twilio.New(),

	}

}

//Names returns the name of every registered provider, in All's order
func Names() []string {

	all := All()
	names := make([]string, 0, len(all))
	for _, p := range all {

		names = append(names, p.Name())

	}
	return names

}

//Filter returns only the providers whose Name() appears in wanted, in All's
//order (not wanted's order, so output stays predictable regardless of how
//--provider flags were repeated on the command line). An empty wanted means
//"every registered provider". This is what makes scan-all the default behavior
//
//An unrecognized name in wanted is a hard error, not silently ignored. A typo'd
//--provider flag should tell the person immediately
func Filter(wanted []string) ([]providers.Provider, error) {

	if len(wanted) == 0 {

		return All(), nil

	}

	want := make(map[string]bool, len(wanted))
	for _, w := range wanted {

		want[w] = true

	}

	for name := range want {

		known := false
		for _, n := range Names() {

			if n == name {

				known = true
				break

			}

		}
		if !known {

			return nil, fmt.Errorf("unknown provider %q (known providers: %s)", name, strings.Join(Names(), ", "))

		}

	}

	var out []providers.Provider
	for _, p := range All() {

		if want[p.Name()] {

			out = append(out, p)

		}

	}

	return out, nil

}