package models

//ProviderFailure records a provider whose Discover() call failed outright
//(e.g. an unreadable credentials file), or a single credential's own
//processing failing during a scan. Surfaced distinctly from a per-credential
//ValidationError - it means something could not even be checked at all, not
//that one specific credential's status is unknown
//
//Lives in models, not in the storage or output package specifically, so
//both can depend on the same shape without either depending on the other -
//storage needs it to persist a scan's failures; output needs it to render
//them. Putting it in either package directly would create a one-way
//dependency the other doesn't actually want
type ProviderFailure struct {

	Provider string `json:"provider"`
	Error    string `json:"error"`

}
