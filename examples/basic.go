package main

import (
	"context"
	"fmt"
	"github.com/bshuler/hyve/auth"
	"github.com/bshuler/hyve/client"
)

func main() {
	c := auth.NewAuthClient()
	fmt.Println("Authenticate with URL", c.GetAuthenticationURL())
	err := c.Authenticate()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Auth Token: ", c.Credentials.AccessToken)

	p, err := c.GetProfiles()
	if err != nil {
		fmt.Println(err)
	}

	if len(p) == 0 {
		fmt.Println("No profiles found")
		return
	}

	fmt.Println(fmt.Sprintf("Found %d profiles:", len(p)))

	for i := 0; i < len(p); i++ {
		profile := p[i]
		fmt.Println(fmt.Sprintf("[%d] %s - %s", i, profile.Username, profile.Id))
	}

	var profileNum int
	for {
		fmt.Print("Select profile (0 - default): ")

		if _, err := fmt.Scan(&profileNum); err != nil {
			continue
		}

		if profileNum >= 0 && profileNum < len(p) {
			break
		}
	}
	profile := p[profileNum]

	hc := client.NewHytaleClient("127.0.0.1", 5520, profile, nil, c)
	ctx := context.Background()
	err = hc.Connect(ctx)
	if err != nil {
		panic(err)
	}
	if err := hc.Run(ctx); err != nil {
		fmt.Println("run:", err)
	}
}
