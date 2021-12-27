/*
Copyright © 2021 Ulrichinho <grolhier.u@gmail.com>
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

var wg sync.WaitGroup

func masksToMap(mask string) (int, bool, error) {
	list := map[string]int{
		"0.0.0.0":         4_294_967_296, //00
		"128.0.0.0":       2_147_483_648, //01
		"196.0.0.0":       1_073_741_824, //02
		"224.0.0.0":       536_870_912,   //03
		"240.0.0.0":       268_435_456,   //04
		"248.0.0.0":       134_217_728,   //05
		"252.0.0.0":       67_108_864,    //06
		"254.0.0.0":       33_554_432,    //07
		"255.0.0.0":       16_777_216,    //08
		"255.128.0.0":     8_388_608,     //09
		"255.196.0.0":     4_194_304,     //10
		"255.224.0.0":     2_097_152,     //11
		"255.240.0.0":     1_048_576,     //12
		"255.248.0.0":     524_288,       //13
		"255.252.0.0":     262_144,       //14
		"255.254.0.0":     131_072,       //15
		"255.255.0.0":     65_536,        //16
		"255.255.128.0":   32_768,        //17
		"255.255.192.0":   16_384,        //18
		"255.255.224.0":   8_192,         //19
		"255.255.240.0":   4_096,         //20
		"255.255.248.0":   2_048,         //21
		"255.255.252.0":   1_024,         //22
		"255.255.254.0":   512,           //23
		"255.255.255.0":   256,           //24
		"255.255.255.128": 128,           //25
		"255.255.255.192": 64,            //26
		"255.255.255.224": 32,            //27
		"255.255.255.240": 16,            //28
		"255.255.255.248": 8,             //29
		"255.255.255.252": 4,             //30
		"255.255.255.254": 2,             //31
		"255.255.255.255": 1,             //32
	}
	for k := range list {
		if k == mask {
			return list[mask], true, nil
		}
	}
	return 0, false, errors.New("[\033[5;38;5;160mERROR\033[0m] not a good mask address")
}

func isValidMask(mask string) bool {
	switch mask {
	case
		"0.0.0.0",         //00
		"128.0.0.0",       //01
		"196.0.0.0",       //02
		"224.0.0.0",       //03
		"240.0.0.0",       //04
		"248.0.0.0",       //05
		"252.0.0.0",       //06
		"254.0.0.0",       //07
		"255.0.0.0",       //08
		"255.128.0.0",     //09
		"255.196.0.0",     //10
		"255.224.0.0",     //11
		"255.240.0.0",     //12
		"255.248.0.0",     //13
		"255.252.0.0",     //14
		"255.254.0.0",     //15
		"255.255.0.0",     //16
		"255.255.128.0",   //17
		"255.255.192.0",   //18
		"255.255.224.0",   //19
		"255.255.240.0",   //20
		"255.255.248.0",   //21
		"255.255.252.0",   //22
		"255.255.254.0",   //23
		"255.255.255.0",   //24
		"255.255.255.128", //25
		"255.255.255.192", //26
		"255.255.255.224", //27
		"255.255.255.240", //28
		"255.255.255.248", //29
		"255.255.255.252", //30
		"255.255.255.254", //31
		"255.255.255.255": //32
		return true
	}
	return false
}

func mtoi(ipaddr string) (mask string, err error) {
	removeExtra := regexp.MustCompile(`^(.*[\\/])`)
	asd := ipaddr[len(ipaddr)-3:]
	findSubnet := removeExtra.ReplaceAll([]byte(asd), []byte(""))
	subnet, err := strconv.ParseInt(string(findSubnet), 10, 64)
	if err != nil {
		return "", errors.New("parse mask: error parsing mask")
	}
	var buff bytes.Buffer
	for i := 0; i < int(subnet); i++ {
		buff.WriteString("1")
	}
	for i := subnet; i < 32; i++ {
		buff.WriteString("0")
	}
	masker := buff.String()
	a, _ := strconv.ParseUint(masker[:8], 2, 64)
	b, _ := strconv.ParseUint(masker[8:16], 2, 64)
	c, _ := strconv.ParseUint(masker[16:24], 2, 64)
	d, _ := strconv.ParseUint(masker[24:32], 2, 64)
	resultMask := fmt.Sprintf("%v.%v.%v.%v", a, b, c, d)
	return resultMask, nil
}

func isCIDRAddr(addr string) bool {
	ip, net, _ := net.ParseCIDR(addr)
	if ip.To4() == nil {
		fmt.Printf("[\033[5;38;5;160mERROR\033[0m] %v is not an IPv4 address (x.x.x.x)\n", ip)
		return false
	}
	mask, _ := mtoi(net.String())
	if !isValidMask(mask) {
		fmt.Printf("[\033[5;38;5;160mERROR\033[0m] %v is not a good mask address\n", mask)
		return false
	}
	return true
}

func ping(ipAddr string) {
	defer wg.Done()
	_, err := exec.Command("ping", ipAddr, "-c 2").Output()
	if err != nil {
		fmt.Printf("🔴 %s\n", ipAddr)
	} else {
		grepEther := exec.Command("grep", "ether")
		arp := exec.Command("arp", ipAddr)

		p, _ := arp.StdoutPipe()
		defer p.Close()

		grepEther.Stdin = p

		arp.Start()

		res, _ := grepEther.Output()

		if string(res) != "" {
			fmt.Printf("🟢 %s\n└── %s", ipAddr, string(res))
		} else {
			fmt.Printf("🟢 %s\n", ipAddr)
		}
	}
}

func main() {
	var target string

	app := &cli.App{
		Name:    "scanoip",
		Usage:   "scan ip network",
		Version: "v1.0.2",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "network",
				Aliases:     []string{"t"},
				Usage:       "define ip target",
				Destination: &target,
				Required:    true,
			},
		},
		Action: func(c *cli.Context) error {
			start := time.Now()

			fmt.Printf("\033[38;5;140m    _____                        ________ \n")
			fmt.Printf("   / ___/_________  ____  ____  /  _/ __ \\\n")
			fmt.Printf("   \\__ \\/ ___/ __ `/ __ \\/ __ \\ / // /_/ /\n")
			fmt.Printf("  ___/ / /__/ /_/ / / / / /_/ // // ____/ \n")
			fmt.Printf(" /____/\\___/\\__,_/_/ /_/\\____/___/_/      \033[0m\n\n")

			if !isCIDRAddr(target) {
				os.Exit(1)
			}

			host := strings.Split(target, "/")

			IPAddr, err := net.ResolveIPAddr("ip", host[0])
			if err != nil {
				fmt.Println("Error in resolving IP")
				os.Exit(1)
			}

			addr := net.ParseIP(IPAddr.String())

			if addr == nil {
				fmt.Println("Invalid address")
				os.Exit(1)
			}

			_, net, _ := net.ParseCIDR(target)
			netmask, _ := mtoi(net.String())
			nbValidAddr, _, err := masksToMap(netmask)
			if err != nil {
				log.Fatal(err)
			}
			network := addr.Mask(net.Mask)

			fmt.Printf("[\033[5;38;5;75mINFO\033[0m] %d addresses to analyse in %s\n", nbValidAddr-2, network)

			ip := strings.Split(network.String(), ".")
			endip, _ := strconv.Atoi(ip[3])

			for i := 1; i < nbValidAddr-1; i++ {
				ip[3] = strconv.Itoa(endip + i)
				ipAddr := strings.Join(ip, ".")
				wg.Add(1)
				go ping(ipAddr)
			}

			wg.Wait()
			end := time.Now()
			fmt.Println(end.Sub(start))

			return nil
		},
	}

	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print only the version",
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
