package gracefulmonitor

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

const apiChain = "OPENSHIFT_APISERVER_REWRITE"

func dnatRule(targetPort, destinationPort int) []string {
	return []string{
		"-m",
		"addrtype",
		"--dst-type",
		"LOCAL",
		"-p",
		"tcp",
		"--dport",
		fmt.Sprintf("%d", targetPort),
		"-j",
		"DNAT",
		"--to-destination",
		fmt.Sprintf(":%d", destinationPort),
	}
}

func establishedDNATRule(targetPort, destinationPort int) []string {
	rule := []string{
		"-m",
		"state",
		"--state",
		"ESTABLISHED,RELATED",
	}
	return append(rule, dnatRule(targetPort, destinationPort)...)
}

func ensureActiveRules(ipt *iptables.IPTables, portMap map[int]int) error {
	// Ensure chain
	exists, err := ipt.ChainExists("nat", apiChain)
	if err != nil {
		return err
	}
	if !exists {
		if err := ipt.NewChain("nat", apiChain); err != nil {
			return err
		}
	}

	// Ensure jump for traffic originating externally (PREROUTING) and
	// internally (OUTPUT).
	jumpRule := []string{"-j", apiChain}
	if err := ipt.AppendUnique("nat", "PREROUTING", jumpRule...); err != nil {
		return err
	}
	if err := ipt.AppendUnique("nat", "OUTPUT", jumpRule...); err != nil {
		return err
	}

	// Ensure the chain contains the desired dnat rules
	dnatRules := map[string][]string{}
	for target, destination := range portMap {
		rule := dnatRule(target, destination)
		// Index by stringified rule to simplify lookup
		key := strings.Join(rule, " ")
		dnatRules[key] = rule
		if err := ipt.AppendUnique("nat", apiChain, rule...); err != nil {
			return err
		}
	}

	// Ensure the chain contains no other rules
	chainRules, err := ipt.List("nat", apiChain)
	if err != nil {
		return err
	}
	// TODO(marun) Will this be valid?
	for _, chainRule := range chainRules {
		if _, ok := dnatRules[chainRule]; ok {
			continue
		}
		if err := ipt.Delete("nat", apiChain, chainRule); err != nil {
			return err
		}
	}

	return nil
}

func ensureTransitionRules(ipt *iptables.IPTables, activeMap, nextMap map[int]int) error {
	// Ensure the chain contains the desired established dnat rules
	dnatRules := map[string][]string{}
	for target, destination := range activeMap {
		rule := establishedDNATRule(target, destination)
		// Index by stringified rule to simplify lookup
		key := strings.Join(rule, " ")
		dnatRules[key] = rule
		if err := ipt.AppendUnique("nat", apiChain, rule...); err != nil {
			return err
		}
	}

	// Ensure the chain contains the desired regular dnat rules
	for target, destination := range nextMap {
		rule := dnatRule(target, destination)
		// Index by stringified rule to simplify lookup
		key := strings.Join(rule, " ")
		dnatRules[key] = rule
		if err := ipt.AppendUnique("nat", apiChain, rule...); err != nil {
			return err
		}
	}

	// Ensure the chain contains no other rules
	chainRules, err := ipt.List("nat", apiChain)
	if err != nil {
		return err
	}
	for _, chainRule := range chainRules {
		if _, ok := dnatRules[chainRule]; ok {
			continue
		}
		// TODO(marun) Need to split chainRule?
		if err := ipt.Delete("nat", apiChain, chainRule); err != nil {
			return err
		}
	}

	return nil
}
