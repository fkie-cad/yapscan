//go:generate go-enum -f=$GOFILE --marshal --lower --names
package procio

// CrashMethod selects a method to crash a process.
/*
ENUM(
CreateThreadOnNull
)
*/
type CrashMethod int
