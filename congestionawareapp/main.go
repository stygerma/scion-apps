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
	conn       *snet.Conn
}

func (c *client) run(remote string) error {
	var err error
	if err = c.init(remote); err != nil {
		return err
	}
	defer c.shutdown()

	err = c.loopSendMessages()
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
	c.conn, err = network.Dial(context.TODO(), "udp", c.clientAddr, c.serverAddr, addr.SvcNone)
	if err != nil {
		return err
	}
	go func() {
		buff := make([]byte, 16384)
		for {
			n, from, err := c.conn.ReadFrom(buff)
			if err != nil {
				panic(err)
			}
			fmt.Printf("conn.Read = %d . From: %v\n", n, from)
		}
	}()
	return nil
}

func (c *client) shutdown() {
	if err := c.conn.Close(); err != nil {
		fmt.Printf("while shutting down: %v\n", err)
	}
}

func (c *client) loopSendMessages() error {
	// every 1 second send a message, for a total of numMsg messages

	const numMsg = 1000
	for i := 0; i < numMsg; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		p := c.selectBestPath()
		message := []byte(fmt.Sprintf("this message (%d) sent using path %v", i, p))
		err := c.SendMessage(p, message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) SendMessage(p snet.Path, msg []byte) error {
	appnet.SetPath(c.serverAddr, p)
	pData := c.paths.Find(PathKey(p))
	if pData == nil {
		return fmt.Errorf("path not found, but in use! %v", p)
	}
	pData.sentPkts++
	_, err := c.conn.WriteTo(msg, c.serverAddr)
	return err
}

func (c *client) selectBestPath() snet.Path {
	var bestPath *PathData
	var bestScore uint64
	for _, p := range c.paths.m {
		score := p.badPkts / (p.sentPkts + 1)
		if score <= bestScore {
			bestScore = score
			bestPath = p
		}
	}
	return bestPath.Path
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var _ snet.SCMPHandler = (*client)(nil)

func (c *client) Handle(pkt *snet.Packet) error {
	p := c.paths.FindFromSpath(pkt.PacketInfo.Path)
	fmt.Printf("Got SCMP. Path=%v\n", p)
	if p == nil {
		panic("logic error: path not found, but in use!")
	}
	p.badPkts++
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	fmt.Printf("scmp handler. hdr = %v\nis scmp header? %v\n", hdr, ok)

	return nil
}

// PathMap stores the keys as strings of the reversed paths.
type PathMap struct {
	m map[string]*PathData
}

type PathData struct {
	Path     snet.Path
	sentPkts uint64
	badPkts  uint64
}

func newPathMap(paths []snet.Path) *PathMap {
	m := &PathMap{
		m: make(map[string]*PathData),
	}
	var alreadyThere bool
	for _, p := range paths {
		key := PathKey(p)
		_, alreadyThere = m.m[key]
		if alreadyThere {
			panic("found two paths sharing the same key!")
		}
		m.m[key] = &PathData{Path: p}
	}
	return m
}

// Len returns how many paths this PathMap contains.
func (m *PathMap) Len() int {
	return len(m.m)
}

// FindFromSpath finds a path data from a path. Returns nil if not found. The path is reversed.
func (m *PathMap) FindFromSpath(p *spath.Path) *PathData {
	fmt.Printf("looking for:\n: %s\n", hex.EncodeToString(p.Raw))
	return m.Find(string(p.Raw))
}

func (m *PathMap) Find(key string) *PathData {
	m.debugPrint()
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

func PathKey(p snet.Path) string {
	spath := p.Path().Copy()
	if err := spath.Reverse(); err != nil {
		panic(err)
	}
	return string(spath.Raw)
}
