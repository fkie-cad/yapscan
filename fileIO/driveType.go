//go:generate go-enum -f=$GOFILE --marshal
package fileIO

/*
ENUM(
Unknown=0
Removable=1
Fixed=2
Remote=4
CDRom=8
RAM=16
)
*/
type DriveType int
