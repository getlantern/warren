// Command survey measures router supply on public Mainline from this host:
// how many DHT nodes per region answer unsolicited traffic. See package
// survey. Region CIDR lists come from files, one prefix per line:
//
//	go run ./cmd/survey -region IR=ir.txt -region RU=ru.txt -for 10m
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/getlantern/warren/natprobe"
	"github.com/getlantern/warren/survey"
)

type regionFlags map[string][]netip.Prefix

func (r regionFlags) String() string { return fmt.Sprint(len(r)) }
func (r regionFlags) Set(s string) error {
	label, path, ok := strings.Cut(s, "=")
	if !ok {
		return fmt.Errorf("want LABEL=file, got %q", s)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		r[label] = append(r[label], p)
	}
	return sc.Err()
}

func main() {
	regions := regionFlags{}
	flag.Var(regions, "region", "LABEL=cidr-file; repeatable")
	dur := flag.Duration("for", 2*time.Minute, "how long to survey")
	rate := flag.Int("rate", 20, "cold probes per second")
	flag.Parse()

	cfg := survey.Config{Bootstrap: natprobe.DefaultBootstrap, ProbesPerSecond: *rate}
	if len(regions) > 0 {
		cfg.Label = survey.PrefixLabeler(regions)
	}
	v, err := survey.NewVantage(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fmt.Println(v.Tally())
			}
		}
	}()
	v.Run(ctx)
	fmt.Println(v.Tally())
}
