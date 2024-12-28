package keys

import "github.com/spf13/cobra"

// GroupID is the ID of the keys group.
const GroupID = "keys"

// Group is the keys group.
var Group = &cobra.Group{
	ID:    GroupID,
	Title: "Keys management:",
}
