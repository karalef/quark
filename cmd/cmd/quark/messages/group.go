package messages

import "github.com/spf13/cobra"

// GroupID is the ID of the messages group.
const GroupID = "messages"

// Group is the messages group.
var Group = &cobra.Group{
	ID:    GroupID,
	Title: "Messages:",
}

const messageExt = ".quark"
