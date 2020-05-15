package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
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
	paths      []snet.Path
	scmpConn   *snet.Conn
}

func (c *client) run(remote string) error {
	var err error
	if err = c.init(); err != nil {
		return err
	}
	defer c.shutdown()
	c.serverAddr, err = appnet.ResolveUDPAddr(remote)
	if err != nil {
		return err
	}
	c.paths, err = appnet.QueryPaths(c.serverAddr.IA)
	if err != nil {
		return err
	}
	fmt.Printf("Found %d paths to destination\n", len(c.paths))
	if len(c.paths) < 2 {
		return fmt.Errorf("This application needs at least two paths to destination")
	}

	conn, err := appnet.DefNetwork().Dial(context.TODO(), "udp", c.clientAddr, c.serverAddr, addr.SvcNone)
	if err != nil {
		return err
	}
	defer conn.Close()

	err = c.loopSendMessages(conn)
	fmt.Println("done.")
	return err
}

func (c *client) init() error {
	var err error
	rand.Seed(88)
	c.clientAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}

	dispatcher := reliable.NewDispatcher("")
	network := snet.NewCustomNetworkWithPR(appnet.DefNetwork().IA,
		&snet.DefaultPacketDispatcherService{
			Dispatcher:  dispatcher,
			SCMPHandler: c,
		},
	)
	c.scmpConn, err = network.Listen(context.TODO(), "udp", c.clientAddr, addr.SvcNone)
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
		appnet.SetPath(c.serverAddr, p)
		message := []byte(fmt.Sprintf("this message (%d) sent using path %v", i, p))
		_, err := conn.WriteTo(message, c.serverAddr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) selectBestPath() snet.Path {
	idx := rand.Intn(len(c.paths))
	return c.paths[idx]
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var _ snet.SCMPHandler = (*client)(nil)

func (c *client) Handle(pkt *snet.Packet) error {
	fmt.Println("SCMP handle")
	return nil
}
