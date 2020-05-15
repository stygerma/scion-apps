package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	localAddrStr = "1-ff00:0:110,127.0.0.1:12345"
	// sciondLocation = "127.0.0.20:30255"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	listeningPort := flag.Uint("port", 0, "[as a server] Port to listen on")
	remoteAddr := flag.String("remote", "", "[as a client] Remote SCION address to connect to.")
	flag.Parse()
	if (*listeningPort > 0) == (*remoteAddr != "") {
		fmt.Println("Must specify only port OR remote")
		return 1
	}
	var err error
	if *listeningPort > 0 {
		err = runServer(uint16(*listeningPort))
	} else {
		err = runClient(*remoteAddr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
func runServer(port uint16) error {
	conn, err := appnet.ListenPort(port)
	check(err)
	defer conn.Close()

	buffer := make([]byte, 16384)
	for {
		n, from, err := conn.ReadFrom(buffer)
		check(err)
		data := buffer[:n]
		fmt.Printf("Received %s: %s\n", from, data)
	}
}

func runClient(remote string) error {
	c := &client{}
	return c.run(remote)
}

type client struct {
	serverAddr *snet.UDPAddr
	clientAddr *net.UDPAddr
	paths      PathMap
	scmpConn   *snet.Conn
}

func (c *client) run(remote string) error {
	var err error
	if err = c.init(remote); err != nil {
		return err
	}
	defer c.shutdown()

	err = c.loopSendMessages(c.scmpConn)
	fmt.Println("done.")
	return err
}

func (c *client) init(remote string) error {
	var err error
	rand.Seed(88)
	c.clientAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	c.serverAddr, err = appnet.ResolveUDPAddr(remote)
	if err != nil {
		return err
	}
	paths, err := appnet.QueryPaths(c.serverAddr.IA)
	if err != nil {
		return err
	}
	fmt.Printf("Found %d paths to destination\n", len(paths))
	if len(paths) < 1 { // TODO(juagargi) it should quit if less than 2
		return fmt.Errorf("This application needs at least two paths to destination")
	}
	c.paths = *newPathMap(paths)

	network := snet.NewCustomNetworkWithPR(appnet.DefNetwork().IA,
		&snet.DefaultPacketDispatcherService{
			Dispatcher:  reliable.NewDispatcher(""),
			SCMPHandler: c,
		},
	)
	c.scmpConn, err = network.Dial(context.TODO(), "udp", c.clientAddr, c.serverAddr, addr.SvcNone)
	if err != nil {
		return err
	}
	go func() {
		buff := make([]byte, 16384)
		for {
			n, from, err := c.scmpConn.ReadFrom(buff)
			if err != nil {
				panic(err)
			}
			fmt.Printf("scmpConn.Read = %d . From: %v\n", n, from)
		}
	}()
	return nil
}

func (c *client) shutdown() {
	if err := c.scmpConn.Close(); err != nil {
		fmt.Printf("while shutting down: %v\n", err)
	}
}

func (c *client) loopSendMessages(conn *snet.Conn) error {
	// every 1 second send a message, for a total of numMsg messages

	const numMsg = 1000
	for i := 0; i < numMsg; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		p := c.selectBestPath()
		// appnet.SetPath(c.serverAddr, p)
		c.serverAddr.Path = p.Path()
		c.serverAddr.NextHop = p.OverlayNextHop()
		message := []byte(fmt.Sprintf("this message (%d) sent using path %v", i, p))
		_, err := conn.WriteTo(message, c.serverAddr)

		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) selectBestPath() snet.Path {
	// idx := rand.Intn(len(c.paths))
	// return c.paths[idx]
	// for _, v := range c.paths.m {
	// 	return v[0]
	// }
	idx := rand.Intn(c.paths.Len())
	i := 0
	for _, p := range c.paths.m {
		if i == idx {
			return p
		}
		i++
	}
	panic("no paths")
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var _ snet.SCMPHandler = (*client)(nil)

func (c *client) Handle(pkt *snet.Packet) error {
	// fmt.Printf("SCMP handle. pkt = %v\n", pkt)
	p := c.paths.Find(*pkt.PacketInfo.Path)
	fmt.Printf("Got SCMP. Path=%v\n", p)
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	fmt.Printf("scmp handler. hdr = %v\nis scmp header? %v\n", hdr, ok)

	return nil
}

// PathMap stores the keys as a CRC of the reversed paths.
type PathMap struct {
	m map[string]snet.Path
}

func newPathMap(paths []snet.Path) *PathMap {
	m := &PathMap{
		// m: make(map[uint32][]snet.Path),
		m: make(map[string]snet.Path),
	}
	for _, p := range paths {
		spath := p.Path().Copy()
		if err := spath.Reverse(); err != nil {
			panic(err)
		}
		key := string(spath.Raw)
		m.m[key] = p
	}
	return m
}

func (m *PathMap) Len() int {
	return len(m.m)
}

// Find finds a path.
func (m *PathMap) Find(p spath.Path) snet.Path {
	fmt.Printf("looking for:\n: %s\n", hex.EncodeToString(p.Raw))
	m.debugPrint()
	key := string(p.Raw)
	stored, found := m.m[key]
	if !found {
		return nil
	}
	fmt.Printf("FOUND!!  %v\n", stored)
	return stored
}

func (m *PathMap) debugPrint() {
	for k := range m.m {
		fmt.Printf("> %s\n", hex.EncodeToString([]byte(k)))
	}
}
