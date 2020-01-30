// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package appnet

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	hostPortRegexp = regexp.MustCompile(`^((?:[-.\da-zA-Z]+)|(?:\d+-[\d:A-Fa-f]+,\[[^\]]+\])):(\d+)$`)
	addrRegexp     = regexp.MustCompile(`^(\d+-[\d:A-Fa-f]+),\[([^\]]+)\]$`)
)

var (
	resolveEtcHosts      resolver
	resolveEtcScionHosts resolver
	resolveRains         resolver
)

// resolver is the interface for the name resolver strategies
// Currently, this is implemented for reading a hosts file and RAINS
type resolver interface {
	// Resolve finds an address for the name
	Resolve(name string) (*snet.SCIONAddress, error)
	// Available returns whether this resolver is currently available (i.e.
	// configuration exists)
	Available() bool
}

type resolverList []resolver

type HostNotFoundError struct {
	host string
}

func (e *HostNotFoundError) Error() string {
	return fmt.Sprintf("host not found: '%s'", e.host)
}

// ResolveUDPAddr parses the address and resolves the hostname.
// The address can be of the form of a SCION address (i.e. of the form "ISD-AS,[IP]:port")
// or in the form of "hostname:port".
func ResolveUDPAddr(address string) (*snet.UDPAddr, error) {
	raddr, err := snet.UDPAddrFromString(address)
	if err == nil {
		return raddr, nil
	}
	hostStr, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	host, err := GetHostByName(hostStr)
	if err != nil {
		return nil, err
	}
	ia := host.IA
	return &snet.UDPAddr{IA: ia, Host: &net.UDPAddr{IP: host.Host.IP(), Port: port}}, nil
}

// SplitHostPort splits a host:port string into host and port variables.
// This is analogous to net.SplitHostPort, which however refuses to handle SCION addresses.
// The address can be of the form of a SCION address (i.e. of the form "ISD-AS,[IP]:port")
// or in the form of "hostname:port".
func SplitHostPort(hostport string) (host, port string, err error) {
	match := hostPortRegexp.FindStringSubmatch(hostport)
	if match != nil {
		return match[1], match[2], nil
	}
	return "", "", fmt.Errorf("appnet.SplitHostPort: invalid address")
}

// GetHostByName returns the address corresponding to hostname
// Returns a HostNotFoundError in case of a successful query where simply
// no matching entry was found.
func GetHostByName(name string) (snet.SCIONAddress, error) {

	resolvers := resolverList{
		resolveEtcHosts,
		resolveEtcScionHosts,
		resolveRains,
	}
	return resolvers.Resolve(name)
}

func (resolvers resolverList) Resolve(name string) (snet.SCIONAddress, error) {

	for _, resolver := range resolvers {
		if resolver != nil && resolver.Available() {
			addr, err := resolver.Resolve(name)
			if err != nil {
				return snet.SCIONAddress{}, err
			} else if addr != nil {
				return *addr, nil
			}
		}
	}
	return snet.SCIONAddress{}, &HostNotFoundError{name}
}

// addrFromString parses a string to a snet.SCIONAddress
// XXX(matzf) this would optimally be part of snet
func addrFromString(address string) (snet.SCIONAddress, error) {
	const iaIndex = 1
	const l3Index = 2

	parts := addrRegexp.FindStringSubmatch(address)
	if parts == nil {
		return snet.SCIONAddress{}, fmt.Errorf("no valid SCION address: %q", address)
	}
	ia, err := addr.IAFromString(parts[iaIndex])
	if err != nil {
		return snet.SCIONAddress{}, fmt.Errorf("invalid IA string: %v", parts[iaIndex])
	}
	var l3 addr.HostAddr
	if hostSVC := addr.HostSVCFromString(parts[l3Index]); hostSVC != addr.SvcNone {
		l3 = hostSVC
	} else {
		l3 = addr.HostFromIPStr(parts[l3Index])
		if l3 == nil {
			return snet.SCIONAddress{}, fmt.Errorf("invalid IP address string: %v", parts[l3Index])
		}
	}
	return snet.SCIONAddress{IA: ia, Host: l3}, nil
}
