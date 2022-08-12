package memory

import "github.com/urfave/cli/v2"

func mapFileAction(c *cli.Context) error {
	return cli.Exit("map file is not supported on windows", 1)
}
