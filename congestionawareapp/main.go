package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	localAddrStr   = "1-ff00:0:110,127.0.0.1:12345"
	DefaultBW      = 10000
	PacketSizeByte = 1000
)

// var (
// 	T0        time.Time
// 	sleepTime time.Duration
// )

var (
	FirstPacket time.Time
	LastPacket  time.Time
)

func parseBandwidth(bw string) int64 {
	rawBw := strings.Split(bw, "bps")
	if len(rawBw[0]) < 1 {
		fmt.Printf("Invalid bandwidth %v provided, using default value %d\n", bw, DefaultBW)
		return DefaultBW
	}

	var m int64
	val := rawBw[0][:len(rawBw[0])-1]
	suffix := rawBw[0][len(rawBw[0])-1:]
	switch suffix {
	case "k":
		m = 1e3
	case "M":
		m = 1e6
	case "G":
		m = 1e9
	case "T":
		m = 1e12
	default:
		m = 1
		val = rawBw[0]
		// ensure that the string ends with a digit
		if !unicode.IsDigit(([]rune(suffix))[0]) {
			fmt.Printf("Invalid bandwidth %v provided, using default value %d\n", val, DefaultBW)
			return DefaultBW
		}
	}

	a4, err := strconv.ParseInt(val, 10, 64)
	if err != nil || a4 < 0 {
		fmt.Printf("Invalid bandwidth %v provided, using default value %d\n", val, DefaultBW)
		return DefaultBW
	}

	return a4 * m
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	listeningPort := flag.Uint("port", 0, "[as a server] Port to listen on")
	remoteAddr := flag.String("remote", "", "[as a client] Remote SCION address to connect to.")
	bw := flag.String("bw", "", "[as client] Bandwidth to send to server")
	numberPkts := flag.Uint("numberPkts", 1000, "Number of packets that should be sent from client to server")
	smartness := flag.Uint("smrt", 1, "If 0 the client won't respond to CWs otherwise it will react")
	flag.Parse()
	if (*listeningPort > 0) == (*remoteAddr != "") {
		fmt.Println("Must specify only port OR remote")
		return 1
	}
	var err error
	if *listeningPort > 0 {
		err = runServer(uint16(*listeningPort))
	} else {
		bandwidth := parseBandwidth(*bw)
		err = runClient(*remoteAddr, bandwidth, *numberPkts, *smartness)
	}
	if err != nil {
		// fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runServer(port uint16) error {
	conn, err := appnet.ListenPort(port)
	err = check(err)
	if err != nil {
		return err
	}
	defer conn.Close()
	buffer := make([]byte, 16384)
	var oldPacketNr int
	var packetNr int
	firstIter := true
	for {
		n, from, err := conn.ReadFrom(buffer) //n, from
		if err != nil {
			return err
		}

		data := buffer[:n]
		if packetNr, err = strconv.Atoi(string(data[bytes.IndexAny(data, "(")+1 : bytes.IndexAny(data, ")")])); err != nil {
			fmt.Println("Unable to convert packet nr to int")
		}
		if packetNr != oldPacketNr+1 && !firstIter {
			fmt.Println("Wrong packet number should get", oldPacketNr+1, "got", packetNr)
		}
		oldPacketNr = packetNr
		firstIter = false
		// fmt.Println("Trying to find number", string(data[bytes.IndexAny(data, "(")+1:bytes.IndexAny(data, ")")]), "packetnr", packetNr)
		fmt.Printf("Received %s: %s, time: %v\n", from, data[:bytes.IndexAny(data, "\n")], time.Now()) //cut off random filler bytes

	}
}

func runClient(remote string, bandwidth int64, numberPkts uint, smartness uint) error {
	c := &client{smartness: smartness}
	return c.run(remote, bandwidth, numberPkts)
}

type client struct {
	serverAddr *snet.UDPAddr
	clientAddr *net.UDPAddr
	paths      PathMap
	// paths      []*PathData
	conn       *snet.Conn
	revHandler snet.RevocationHandler
	smartness  uint
}

func (c *client) run(remote string, bandwidth int64, numberPkts uint) error {
	var err error
	if err = c.init(remote); err != nil {
		return err
	}
	defer c.shutdown()

	err = c.loopSendMessages(bandwidth, numberPkts)
	fmt.Println("done.")
	fmt.Println("Results for the paths\n")
	var packetsTotal uint64
	for _, p := range c.paths.m {
		fmt.Println("Path", p.Path, "Packets sent", p.sentPkts, "CWs received", p.badPkts)
		packetsTotal += p.sentPkts
	}
	fmt.Println("packets total", packetsTotal, "PacketSizeByte", PacketSizeByte, "exevution time", uint64(LastPacket.Sub(FirstPacket)))
	fmt.Println("Approximated BW", float64((packetsTotal)*PacketSizeByte*8*1000)/float64(LastPacket.Sub(FirstPacket)), "Mbps")
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
	// c.paths = *newPathSlice(paths)

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
				// panic(err)
				fmt.Println("Got error while reading connection on client side", err)
				return
			}
			fmt.Printf("conn.Read = %d . From: %v\n", n, from)
		}
	}()
	return nil
}

func (c *client) shutdown() {
	c.conn.SetReadDeadline(time.Now()) //Avoids blocking read
	time.Sleep(time.Nanosecond * 1000)
	if err := c.conn.Close(); err != nil {
		fmt.Printf("while shutting down: %v\n", err)
	}
}

func (c *client) loopSendMessages(bandwidth int64, numberPkts uint) error {
	// every 1 second send a message, for a total of numMsg messages
	var t0 time.Time //
	t0 = time.Now()
	// const pktSizeByte = 1000
	pktSizeBit := PacketSizeByte * 8
	sleepTime := time.Duration(pktSizeBit * 1000000000 / int(bandwidth))
	fmt.Println("Bandwidth", bandwidth, "Number of packets", numberPkts, "sleepTime", sleepTime, "approximated run time", numberPkts*uint(pktSizeBit)/uint(bandwidth))
	var p snet.Path
	// const numMsg = numberPkts
	for i := 0; i < int(numberPkts); i++ {
		if i == 0 {
			FirstPacket = time.Now()
			t := time.Now()
			p = c.selectFirstPath()
			tt := time.Now()
			fmt.Println("Iteration", i, "Before select best path", t, "After select best path", tt, "Difference", tt.Sub(t))
		}
		if i == int(numberPkts)-1 {
			LastPacket = time.Now()
		}
		if i > 0 && i%15 == 0 && c.smartness > 0 {
			t := time.Now()
			p = c.selectBestPath()
			tt := time.Now()
			fmt.Println("Iteration", i, "Before select best path", t, "After select best path", tt, "Difference", tt.Sub(t))
		}
		message := []byte(fmt.Sprintf("this message (%d) sent using path %v \n", i, p))
		fillLength := PacketSizeByte - len(message)
		filler := make([]byte, fillLength)
		_, err := rand.Read(filler)
		message = append(message, filler...)
		// fmt.Println("filled message", "number of filler bytes", n, "err", err, "message", message[:128])
		// message := []byte(fmt.Sprintf("sent message using path %v", p))
		err = c.SendMessage(p, message, t0, sleepTime, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) SendMessage(p snet.Path, msg []byte, t0 time.Time, sleepTime time.Duration, i int) error {
	appnet.SetPath(c.serverAddr, p)
	// var pData *PathData
	pData := c.paths.Find(PathKey(p))
	// if c.paths[0].Path.Fingerprint() == p.Fingerprint() {
	// pData = c.paths[0]
	// } else if c.paths[1].Path.Fingerprint() == p.Fingerprint() {
	// pData = c.paths[1]
	// }
	if pData == nil {
		return fmt.Errorf("path not found, but in use! %v", p)
	}
	if i == 0 {
		t0 = time.Now()
	}
	pData.sentPkts++
	t1 := time.Now()
	t2 := t0.Add(sleepTime * time.Duration(i))
	if t1.Before(t2) {
		fmt.Println("sleeping")
		time.Sleep(t2.Sub(t1))
	}
	fmt.Println("Time", time.Now(), "Packet about to be sent", "i", i, "t1", t1, "t2", t2)
	_, err := c.conn.WriteTo(msg, c.serverAddr)
	return err
}

func (c *client) selectFirstPath() snet.Path {
	var firstPath *PathData
	firstScore := 0
	for _, p := range c.paths.m {
		score := p.Path.OverlayNextHop().Port
		fmt.Println("Select first path", "overlay next hop port", p.Path.OverlayNextHop().Port, "path", p.Path)

		if score > firstScore {
			firstScore = score
			firstPath = p
		}
	}
	fmt.Println("Chosen path", firstPath.Path, "best score", firstScore, "\n")
	return firstPath.Path
}

func (c *client) selectBestPath() snet.Path {
	var bestPath *PathData
	var bestScore float64
	bestScore = 10
	for _, p := range c.paths.m {
		// p0 := c.paths[0]
		// score0 := float64(p0.badPkts) / float64(p0.sentPkts+1)
		// fmt.Println("Select best path", "sentPkts", p0.sentPkts, "badPkts", p0.badPkts, "score", score0, "path", p0.Path)
		score := float64(p.badPkts) / float64(p.sentPkts+1)
		// p1 := c.paths[1]
		// score1 := float64(p1.badPkts) / float64(p1.sentPkts+1)
		fmt.Println("Select best path", "sentPkts", p.sentPkts, "badPkts", p.badPkts, "score", score, "path", p.Path)
		if score <= bestScore {
			bestScore = score
			bestPath = p
			// if score0 <= score1 {
			// 	bestScore = score0
			// 	bestPath = p0
			// } else {
			// 	bestScore = score1
			// 	bestPath = p1
		}
	}
	fmt.Println("Chosen path", bestPath.Path, "best score", bestScore, "\n")
	return bestPath.Path
}

func check(err error) error {
	if err != nil {
		fmt.Println("Received error in check", err)
		// panic(err)
		return err
	}
	return nil
}

var _ snet.SCMPHandler = (*client)(nil)

func (c *client) Handle(pkt *snet.Packet) error {
	p := c.paths.FindFromSpath(pkt.PacketInfo.Path)
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	if ok {
		fmt.Println("Got SCMP", "Class", hdr.Class, "Type", hdr.Type)
	}
	if ok && hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF {
		p.badPkts++
		fmt.Println("Got new IF revocation message, path:", p)
		c.handleSCMPRev(hdr, pkt)
		return nil
	}
	// if err := pkt.Path.Reverse(); err != nil {
	// 	panic("Unable to reverse path")
	// }

	// var p *PathData
	// fmt.Println("Comparing path 0 local\n", hex.EncodeToString([]byte(c.PathKey(0))), "incoming\n", hex.EncodeToString([]byte(pkt.PacketInfo.Path.Raw)))
	// fmt.Println("Comparing path 1 local\n", hex.EncodeToString([]byte(c.PathKey(1))), "incoming\n", hex.EncodeToString([]byte(pkt.PacketInfo.Path.Raw)))

	// if string(c.PathKey(0)) == string(pkt.PacketInfo.Path.Raw) { // string(c.paths[0].Path.Path().Raw) (bytes.Compare(c.paths[0].Path.Path().Raw, pkt.PacketInfo.Path.Raw)) == 0	//c.paths[0].Path.Path().InfOff == pkt.PacketInfo.Path.InfOff && c.paths[0].Path.Path().HopOff == pkt.PacketInfo.Path.HopOff &&
	// 	p = c.paths[0]
	// } else if string(c.PathKey(1)) == string(pkt.PacketInfo.Path.Raw) { //string(c.paths[0].Path.Path().Raw)  c.paths[1].Path.Path().InfOff == pkt.PacketInfo.Path.InfOff && c.paths[1].Path.Path().HopOff == pkt.PacketInfo.Path.HopOff &&
	// 	p = c.paths[1]
	// }
	fmt.Printf("Got SCMP. Path=%v\n", p)
	if p == nil {
		panic("logic error: path not found, but in use!")
	}
	if ok && c.smartness > 0 && (hdr.Class == scmp.C_General && (hdr.Type == scmp.T_G_BasicCongWarn || hdr.Type == scmp.T_G_StochasticCongWarn)) {
		p.badPkts++
		fmt.Println("Got new SCMP notification message, path:", p)
	}

	return nil
}

// PathMap stores the keys as strings of the reversed paths.
type PathMap struct {
	m map[string]*PathData
}

type PathSlice []*PathData

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
	// fmt.Printf("looking for:\n: %s\n", hex.EncodeToString(p.Raw))
	return m.Find(string(p.Raw))
}

func (m *PathMap) Find(key string) *PathData {
	// m.debugPrint()
	stored, found := m.m[key]
	if !found {
		return nil
	}
	// fmt.Printf("FOUND!!  %v\n", stored)
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

func (c *client) handleSCMPRev(hdr *scmp.Hdr, pkt *snet.Packet) {
	scmpPayload, ok := pkt.Payload.(*scmp.Payload)
	if !ok {
		fmt.Println("Unable to type assert payload to SCMP payload", nil,
			"type", common.TypeOf(pkt.Payload))
		return
	}
	info, ok := scmpPayload.Info.(*scmp.InfoRevocation)
	if !ok {
		fmt.Println("Unable to type assert SCMP Info to SCMP Revocation Info", nil,
			"type", common.TypeOf(scmpPayload.Info))
		return
	}
	fmt.Println("Received SCMP revocation", "header", hdr.String(), "payload", scmpPayload.String(),
		"src", pkt.Source)
	if c.revHandler != nil {
		c.revHandler.RevokeRaw(context.TODO(), info.RawSRev)
	}
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(info.RawSRev)
	if err != nil {
		fmt.Println("err", err)
		return
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		fmt.Println("err", err)
	}
	fmt.Println("End of handleSCMPRev", "hdr", hdr, "revInfo", revInfo)
}
