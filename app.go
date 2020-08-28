package yapscan

import (
	"github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

func initAppAction(c *cli.Context) error {
	lvl, err := logrus.ParseLevel(c.String("log-level"))
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	return nil
}

func main(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	return nil
}

func RunApp(args []string) {
	app := &cli.App{
		Name:    "yapscan",
		Version: "0.1.0",
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Luca Corbatto",
				Email: "luca.corbatto@fkie.fraunhofer.de",
			},
		},
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "one of [trace, debug, info, warn, error, fatal]",
				Value:   "info",
			},
		},
		Action: main,
	}

	err := app.Run(args)
	if err != nil {
		logrus.Fatal(err)
	}
}
