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

// demoappserver application
// For more documentation on the application see:
// https://github.com/netsec-ethz/scion-apps/blob/master/README.md
// https://github.com/netsec-ethz/scion-apps/blob/master/demoapper/README.md
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"sync"
	"time"

	. "github.com/netsec-ethz/scion-apps/demoapp/demoapplib"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	resultsMap     map[string]*DemoappResult
	resultsMapLock sync.Mutex
	currentDemoapp string // Contains connection parameters, in case server's ack packet was lost
	DCConn         *snet.Conn
	enderSend      *chan struct{}
	enderReceive   *chan struct{}
	killerSend     *chan struct{}
	killerReceive  *chan struct{}
	killedReceive  sync.Mutex
	killedSend     sync.Mutex
	resultsReady   sync.Mutex
	endedAlready   bool
	resultsSent    bool
)

// Deletes the old entries in resultsMap
func purgeOldResults() {
	for {
		time.Sleep(time.Minute * time.Duration(5))
		resultsMapLock.Lock()
		// Erase entries that are older than 1 minute
		t := time.Now().Add(-time.Minute)
		for k, v := range resultsMap {
			if v.ExpectedFinishTime.Before(t) {
				delete(resultsMap, k)
			}
		}
		resultsMapLock.Unlock()
	}
}

func main() {
	resultsMap = make(map[string]*DemoappResult)
	go purgeOldResults()

	// Fetch arguments from command line
	serverPort := flag.Uint("p", 40002, "Port")
	// id := flag.String("id", "demoapp", "Element ID")
	// logDir := flag.String("log_dir", "./logs", "Log directory")

	flag.Parse()

	// Setup logging
	// if _, err := os.Stat(*logDir); os.IsNotExist(err) {
	// 	err := os.Mkdir(*logDir, 0744)
	// 	if err != nil {
	// 		LogFatal("Unable to create log dir", "err", err)
	// 	}
	// }
	// log.Root().SetHandler(log.MultiHandler(
	// 	log.LvlFilterHandler(log.LvlDebug,
	// 		log.StreamHandler(os.Stderr, fmt15.Fmt15Format(fmt15.ColorMap))),
	// 	log.LvlFilterHandler(log.LvlDebug,
	// 		log.Must.FileHandler(fmt.Sprintf("%s/%s.log", *logDir, *id),
	// 			fmt15.Fmt15Format(nil)))))

	err := runServer(uint16(*serverPort))
	if err != nil {
		LogFatal("Unable to start server", "err", err)
	}
}

func runServer(port uint16) error {
	conn, err := appnet.ListenPort(port)
	if err != nil {
		return err
	}

	receivePacketBuffer := make([]byte, 2500)
	sendPacketBuffer := make([]byte, 2500)
	handleClients(conn, receivePacketBuffer, sendPacketBuffer)
	return nil
}

func handleClients(CCConn *snet.Conn, receivePacketBuffer []byte, sendPacketBuffer []byte) {
	firstRun := true
	killedPrevious := false
	for {
		// fmt.Println("Are we getting here?108")

		// Handle client requests
		n, fromAddr, err := CCConn.ReadFrom(receivePacketBuffer)
		clientCCAddr := fromAddr.(*snet.UDPAddr)
		if err != nil {
			// Todo: check error in detail, but for now simply continue
			continue
		}
		if n < 1 {
			continue
		}

		t := time.Now()
		// Check if a current test is ongoing, and if it completed
		if len(currentDemoapp) > 0 {
			v, ok := resultsMap[currentDemoapp]
			if !ok {
				// This can only happen if client aborted and never picked up results
				// then information got removed by purgeOldResults goroutine
				currentDemoapp = ""
			} else if t.After(v.ExpectedFinishTime) {
				// The demoapp should be finished by now, check if results are written
				if v.NumPacketsReceived >= 0 {
					// Indeed, the demoapp has completed
					currentDemoapp = ""
				}
			}
		}
		// fmt.Println("Are we getting here?137")

		clientCCAddrStr := clientCCAddr.String()
		fmt.Println("Received request:", clientCCAddrStr, "time", time.Now().Format("2006-01-02 15:04:05.000000"))

		if receivePacketBuffer[0] == 'N' {
			// New demoapp request
			fmt.Println("\n\nNew demoapp request")

			//When receiving a new demoapp request while still working on a previous iteration
			// we kill the previous iteration since the client already moved on and does not want
			// the previous results
			if !firstRun && currentDemoapp != "" {
				fmt.Println("Killing previous connection")
				currentDemoapp = ""
				DCConn.SetReadDeadline(time.Now())
				close(*killerSend)
				close(*killerReceive)
				time.Sleep(time.Nanosecond * 4000000)
				fmt.Println("killed sender")
				killedSend.Lock()
				fmt.Println("Able to lock killedsenderlock")
				killedSend.Unlock()
				fmt.Println("killed receiver")
				killedReceive.Lock()
				fmt.Println("Able to lock killedreceiverlock")
				killedSend.Unlock()
				fmt.Println("Killed previous connection")
				killedPrevious = true
			}

			fmt.Println("currentDemoapp", currentDemoapp)
			if len(currentDemoapp) != 0 && false {
				fmt.Println(("Entered the if clause around line 150 in receiver"))
				fmt.Println("A demoapp is already ongoing", clientCCAddrStr)
				if clientCCAddrStr == currentDemoapp {
					// The request is from the same client for which the current test is already ongoing
					// If the response packet was dropped, then the client would send another request
					// We simply send another response packet, indicating success
					fmt.Println("error, clientCCAddrStr == currentDemoapp")
					sendPacketBuffer[0] = 'N'
					sendPacketBuffer[1] = byte(0)
					_, _ = CCConn.WriteTo(sendPacketBuffer[:2], clientCCAddr)
					// Ignore error
					continue
				}

				// The request is from a different client
				// A demoapp is currently ongoing, so send back remaining duration
				resultsMapLock.Lock()
				v, ok := resultsMap[currentDemoapp]
				if !ok {
					// This should never happen
					resultsMapLock.Unlock()
					continue
				}
				resultsMapLock.Unlock()

				// Compute for how much longer the current test is running
				remTime := t.Sub(v.ExpectedFinishTime)
				sendPacketBuffer[0] = 'N'
				sendPacketBuffer[1] = byte(remTime/time.Second) + 1
				_, _ = CCConn.WriteTo(sendPacketBuffer[:2], clientCCAddr)
				// Ignore error
				continue
			}

			endedAlready = false
			resultsSent = false

			// This is a new request
			clientBwp, n1, err := DecodeDemoappParameters(receivePacketBuffer[1:])
			if err != nil {
				fmt.Println("Decoding error, err", err)
				// Decoding error, continue
				continue
			}
			fmt.Println("Decoded client parameters")
			serverBwp, n2, err := DecodeDemoappParameters(receivePacketBuffer[n1+1:])
			if err != nil {
				fmt.Println("Decoding error")
				// Decoding error, continue
				continue
			}
			fmt.Println("Decoded server parameters")
			if n != 1+n1+n2 {
				fmt.Println("Error, packet size incorrect")
				// Do not send a response packet for malformed request
				continue
			}
			fmt.Println("checked length")

			// Address of client Data Connection (DC)
			clientDCAddr := clientCCAddr.Copy()
			clientDCAddr.Host.Port = int(clientBwp.Port)

			// Address of server Data Connection (DC)
			serverCCAddr := CCConn.LocalAddr().(*net.UDPAddr)
			serverDCAddr := &net.UDPAddr{IP: serverCCAddr.IP, Port: int(serverBwp.Port)}

			// Open Data Connection
			DCConn, err = appnet.DefNetwork().Dial(
				context.TODO(), "udp", serverDCAddr, clientDCAddr, addr.SvcNone)
			// if err != nil {
			// 	if err.Error() == "EOF" {
			// 		fmt.Println("entered if clause ")
			// 		// DCConn.Close()
			// 		DCConn, err = appnet.DefNetwork().Dial(
			// 			context.TODO(), "udp", serverDCAddr, clientDCAddr, addr.SvcNone)
			// 	}
			// }
			// DCConn, err = appnet.ListenPort(uint16(serverDCAddr.Port))
			if err != nil {
				// An error happened, ask the client to try again in 1 second
				sendPacketBuffer[0] = 'N'
				sendPacketBuffer[1] = byte(1)
				_, _ = CCConn.WriteTo(sendPacketBuffer[:2], clientCCAddr)
				// Ignore error
				fmt.Println("Error while opening data connection, err:", err)
				continue
			}
			fmt.Println("opened data connection")

			// Nothing needs to be added to account for network delay, since sending starts right away
			expFinishTimeSend := t.Add(serverBwp.DemoappDuration + GracePeriodSend)
			expFinishTimeReceive := t.Add(clientBwp.DemoappDuration + StragglerWaitPeriod)
			// We use resultsMapLock also for the bres variable
			bres := DemoappResult{
				NumPacketsReceived: -1,
				CorrectlyReceived:  -1,
				IPAvar:             -1,
				IPAmin:             -1,
				IPAavg:             -1,
				IPAmax:             -1,
				PrgKey:             clientBwp.PrgKey,
				ExpectedFinishTime: expFinishTimeReceive,
			}
			if expFinishTimeReceive.Before(expFinishTimeSend) {
				// The receiver will close the DC connection, so it will wait long enough until the
				// sender is also done
				bres.ExpectedFinishTime = expFinishTimeSend
			}
			resultsMapLock.Lock()
			resultsMap[clientCCAddrStr] = &bres
			resultsMapLock.Unlock()

			if firstRun || killedPrevious {
				killedReceive.Lock()
				killedSend.Lock()
				fmt.Println("Locked killLocks")

			}
			resultsReady = sync.Mutex{}
			// go HandleDCConnReceive(clientBwp, DCConn, resChan)
			enderReceive, killerReceive = HandleDCConnReceiveServer(clientBwp, DCConn, &bres, &resultsMapLock, &resultsReady, &killedReceive)
			enderSend, killerSend = HandleDCConnSendServer(serverBwp, DCConn, &killedSend) //, clientDCAddr
			resultsReady.Lock()
			// Send back success
			sendPacketBuffer[0] = 'N'
			sendPacketBuffer[1] = byte(0)
			_, _ = CCConn.WriteTo(sendPacketBuffer[:2], clientCCAddr)
			// Ignore error
			// Everything succeeded, now set variable that demoapp is ongoing
			currentDemoapp = clientCCAddrStr
			// fmt.Println("Are we getting here? 255")
			firstRun = false
		} else if receivePacketBuffer[0] == 'R' {
			// This is a request for the results
			if resultsSent {
				continue
			}
			fmt.Println("New results request:", time.Now().Format("2006-01-02 15:04:05.000000"))

			sendPacketBuffer[0] = 'R'
			// Make sure that the client is known and that the results are ready
			v, ok := resultsMap[clientCCAddrStr]
			if !ok {
				// There are no results for this client, return an error
				fmt.Println("No available results for client", "ok", ok)
				sendPacketBuffer[1] = byte(127)
				_, _ = CCConn.WriteTo(sendPacketBuffer[:2], clientCCAddr)
				continue
			}
			// Make sure the PRG key is correct
			if n != 1+len(v.PrgKey) || !bytes.Equal(v.PrgKey, receivePacketBuffer[1:1+len(v.PrgKey)]) {
				// Error, the sent PRG is incorrect
				fmt.Println("PRG key is incorrect ")
				sendPacketBuffer[1] = byte(127)
				_, _ = CCConn.WriteTo(sendPacketBuffer[:2], clientCCAddr)
				continue
			}

			//Stop reading in receiver, avoids blocking from readfunction
			if !endedAlready {
				enforcedFinish := time.Now()

				close(*enderReceive)
				close(*enderSend)
				_ = DCConn.SetReadDeadline(enforcedFinish)

				endedAlready = true
				fmt.Println("Sent ender in receiver, time:", time.Now().Format("2006-01-02 15:04:05.000000"))
				resultsReady.Lock()
				resultsReady.Unlock()
			}

			// Note: it would be better to have the resultsMap key consist only of the PRG key,
			// so that a repeated demoapp from the same client with the same port gets a
			// different resultsMap entry. However, in practice, a client would not run concurrent
			// demoapps, as long as the results are fetched before a new demoapp is initiated, this
			// code will work fine.
			if v.NumPacketsReceived == -1 {
				// The results are not yet ready
				if t.After(v.ExpectedFinishTime) {
					// The results should be ready, but are not yet written into the data
					// structure, so let's let client wait for 1 second
					sendPacketBuffer[1] = byte(1)
				} else {
					sendPacketBuffer[1] = byte(1)
				}
				_, _ = CCConn.WriteTo(sendPacketBuffer[:n], clientCCAddr)
				continue
			}
			sendPacketBuffer[1] = byte(0)
			n = EncodeDemoappResult(v, sendPacketBuffer[2:])
			_, _ = CCConn.WriteTo(sendPacketBuffer[:n+2], clientCCAddr)
			fmt.Println("Sent results from server", "time", time.Now().Format("2006-01-02 15:04:05.000000"))
			currentDemoapp = ""
			resultsSent = true
		}
	}
}
