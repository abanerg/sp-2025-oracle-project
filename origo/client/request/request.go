package request

import (
	"bufio"
	tls "client/tls_fork"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"

	// "crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type RequestTLS struct {
	ServerDomain    string
	ServerPath      string
	ProxyURL        string
	UrlPrivateParts string
	AccessToken     string
	StorageLocation string
}

type RequestData struct {
	secrets   map[string][]byte
	recordMap map[string]tls.RecordMeta
}

// func NewRequest() RequestTLS {
// 	return RequestTLS{
// 		ServerDomain:    "localhost",
// 		ServerPath:      "/my-btc-usdt-order", // "testserver.origodata.io"
// 		ProxyURL:        "localhost:8082",
// 		UrlPrivateParts: "",
// 		AccessToken:     "",
// 		StorageLocation: "./local_storage/",
// 	}
// }

func NewRequest() RequestTLS {
	return RequestTLS{
		ServerDomain:    "api.github.com",
		ServerPath:      "/", // "testserver.origodata.io"
		ProxyURL:        "localhost:8082",
		UrlPrivateParts: "",
		AccessToken:     "",
		StorageLocation: "./local_storage/",
	}
}

func (r *RequestTLS) Store(data RequestData) error {
	jsonData := make(map[string]map[string]string)
	jsonData["keys"] = make(map[string]string)

	for k, v := range data.secrets {
		jsonData["keys"][k] = hex.EncodeToString(v)
	}
	for k, v := range data.recordMap {
		jsonData[k] = make(map[string]string)
		jsonData[k]["typ"] = v.Typ
		jsonData[k]["additionalData"] = hex.EncodeToString(v.AdditionalData)
		jsonData[k]["payload"] = hex.EncodeToString(v.Payload)
		jsonData[k]["ciphertext"] = hex.EncodeToString(v.Ciphertext)
	}

	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = os.WriteFile(r.StorageLocation+"session_params_13.json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
	}
	return err
}

// func (r *RequestTLS) Store(data RequestData) error {
// 	jsonData := make(map[string]map[string]string)
// 	jsonData["keys"] = make(map[string]string)

// 	for k, v := range data.secrets {
// 		jsonData["keys"][k] = hex.EncodeToString(v)
// 	}

// 	// Process the record map
// 	for k, v := range data.recordMap {
// 		jsonData[k] = make(map[string]string)
// 		jsonData[k]["typ"] = v.Typ
// 		jsonData[k]["additionalData"] = hex.EncodeToString(v.AdditionalData)

// 		// Check if this is a Server Record (SR)
// 		if v.Typ == "SR" && v.Payload != nil && len(v.Payload) > 0 {
// 			// Debug: Print what type of payload we're getting
// 			fmt.Println("Processing payload of type:", v.Typ)

// 			// Decode the payload to check its content
// 			payloadStr := string(v.Payload)

// 			// For HTTP responses, we need to process them differently
// 			if strings.HasPrefix(payloadStr, "HTTP/") {
// 				fmt.Println("Detected HTTP response")

// 				// Process HTTP response into structured JSON
// 				processedPayload := processHTTPResponse(payloadStr)
// 				jsonData[k]["payload"] = hex.EncodeToString([]byte(processedPayload))

// 				// Add this to see the complete structure
// 				var prettyJSON bytes.Buffer
// 				if err := json.Indent(&prettyJSON, []byte(processedPayload), "", "  "); err == nil {
// 					fmt.Println("Complete HTTP JSON structure:")
// 					fmt.Println(prettyJSON.String())
// 				} else {
// 					fmt.Println("Error pretty printing JSON:", err)
// 				}

// 				// Debug: Print a sample of what we're storing
// 				fmt.Println("Processed HTTP payload (first 100 chars):")
// 				if len(processedPayload) > 100 {
// 					fmt.Println(processedPayload[:100] + "...")
// 				} else {
// 					fmt.Println(processedPayload)
// 				}
// 			} else {
// 				// Original behavior for non-HTTP content
// 				jsonData[k]["payload"] = hex.EncodeToString(v.Payload)
// 			}
// 		} else {
// 			// Original behavior for other record types
// 			jsonData[k]["payload"] = hex.EncodeToString(v.Payload)
// 		}

// 		jsonData[k]["ciphertext"] = hex.EncodeToString(v.Ciphertext)
// 	}

// 	// Print the structure before marshaling to JSON
// 	fmt.Println("===== JSON Data Structure =====")
// 	for recordKey, recordMap := range jsonData {
// 		if recordKey == "keys" {
// 			// Skip printing key details for security
// 			fmt.Printf("Record Key: %s (key details omitted)\n", recordKey)
// 			continue
// 		}

// 		fmt.Printf("Record Key: %s\n", recordKey)
// 		for fieldName, fieldValue := range recordMap {
// 			if fieldName == "payload" || fieldName == "ciphertext" {
// 				fmt.Printf("  Field: %s = (length: %d bytes)\n",
// 					fieldName, len(fieldValue)/2) // Divide by 2 since hex encoding doubles length
// 			} else {
// 				fmt.Printf("  Field: %s = %s\n", fieldName, fieldValue)
// 			}
// 		}
// 		fmt.Println()
// 	}
// 	fmt.Println("==============================")

// 	file, err := json.MarshalIndent(jsonData, "", " ")
// 	if err != nil {
// 		log.Error().Err(err).Msg("json.MarshalIndent")
// 		return err
// 	}

// 	// Write the file
// 	err = os.WriteFile(r.StorageLocation+"session_params_13.json", file, 0644)
// 	if err != nil {
// 		log.Error().Err(err).Msg("os.WriteFile")
// 	} else {
// 		fmt.Println("Successfully wrote session_params_13.json")

// 		// Read it back to verify content (optional)
// 		readBack, readErr := os.ReadFile(r.StorageLocation + "session_params_13.json")
// 		if readErr == nil {
// 			fmt.Println("File size:", len(readBack), "bytes")
// 		}
// 	}

// 	return err
// }

// func (r *RequestTLS) Store(data RequestData) error {
// 	jsonData := make(map[string]map[string]string)
// 	jsonData["keys"] = make(map[string]string)

// 	for k, v := range data.secrets {
// 		jsonData["keys"][k] = hex.EncodeToString(v)
// 	}

// 	// Process the record map
// 	for k, v := range data.recordMap {
// 		jsonData[k] = make(map[string]string)
// 		jsonData[k]["typ"] = v.Typ
// 		jsonData[k]["additionalData"] = hex.EncodeToString(v.AdditionalData)

// 		// Only process application data (SR) records - NOT handshake records
// 		if v.Typ == "SR" && v.Payload != nil && len(v.Payload) > 0 {
// 			htmlContent := string(v.Payload)

// 			// Check if it starts with HTTP
// 			if strings.HasPrefix(htmlContent, "HTTP/") {
// 				// Process HTTP response into structured JSON
// 				processedPayload := processHTTPResponse(htmlContent)
// 				jsonData[k]["payload"] = hex.EncodeToString([]byte(processedPayload))
// 			} else {
// 				// Original behavior for non-HTTP content
// 				jsonData[k]["payload"] = hex.EncodeToString(v.Payload)
// 			}
// 		} else {
// 			// IMPORTANT: Do not modify handshake or other record types!
// 			jsonData[k]["payload"] = hex.EncodeToString(v.Payload)
// 		}

// 		jsonData[k]["ciphertext"] = hex.EncodeToString(v.Ciphertext)
// 	}

// 	file, err := json.MarshalIndent(jsonData, "", " ")
// 	if err != nil {
// 		log.Error().Err(err).Msg("json.MarshalIndent")
// 		return err
// 	}
// 	err = os.WriteFile(r.StorageLocation+"session_params_13.json", file, 0644)
// 	if err != nil {
// 		log.Error().Err(err).Msg("os.WriteFile")
// 	}
// 	return err
// }

// func (r *RequestTLS) Store(data RequestData) error {
// 	jsonData := make(map[string]map[string]string)
// 	jsonData["keys"] = make(map[string]string)

// 	for k, v := range data.secrets {
// 		jsonData["keys"][k] = hex.EncodeToString(v)
// 	}

// 	// Process the record map
// 	for k, v := range data.recordMap {
// 		jsonData[k] = make(map[string]string)
// 		jsonData[k]["typ"] = v.Typ
// 		jsonData[k]["additionalData"] = hex.EncodeToString(v.AdditionalData)
// 		jsonData[k]["ciphertext"] = hex.EncodeToString(v.Ciphertext)

// 		// Store ORIGINAL payload - important for TLS record integrity
// 		jsonData[k]["payload"] = hex.EncodeToString(v.Payload)

// 		// Only AFTER storing the original payload, add a processed version
// 		// This keeps the original data intact for TLS verification
// 		if v.Typ == "SR" && v.Payload != nil && len(v.Payload) > 0 {
// 			htmlContent := string(v.Payload)
// 			if strings.HasPrefix(htmlContent, "HTTP/") {
// 				processedJSON := processHTTPResponse(htmlContent)
// 				jsonData[k]["processed_payload"] = processedJSON
// 			}
// 		}
// 	}

// 	file, err := json.MarshalIndent(jsonData, "", " ")
// 	if err != nil {
// 		log.Error().Err(err).Msg("json.MarshalIndent")
// 		return err
// 	}
// 	err = os.WriteFile(r.StorageLocation+"session_params_13.json", file, 0644)
// 	if err != nil {
// 		log.Error().Err(err).Msg("os.WriteFile")
// 	}
// 	return err
// }

// // processHTTPResponse extracts relevant information from an HTTP response and returns it as a JSON string
// func processHTTPResponse(httpResponse string) string {
// 	// Create a structured representation of the HTTP response
// 	responseData := make(map[string]interface{})

// 	// Split headers and body
// 	parts := strings.SplitN(httpResponse, "\r\n\r\n", 2)

// 	// Process headers
// 	headers := make(map[string]string)
// 	headerLines := strings.Split(parts[0], "\r\n")

// 	// First line is the status line
// 	if len(headerLines) > 0 {
// 		responseData["status"] = headerLines[0]
// 	}

// 	// Extract other headers
// 	for i := 1; i < len(headerLines); i++ {
// 		headerParts := strings.SplitN(headerLines[i], ": ", 2)
// 		if len(headerParts) == 2 {
// 			headers[headerParts[0]] = headerParts[1]
// 		}
// 	}
// 	responseData["headers"] = headers

// 	// Process body if it exists
// 	if len(parts) > 1 && len(parts[1]) > 0 {
// 		body := parts[1]

// 		// Check if body is HTML
// 		isHTML := strings.Contains(strings.ToLower(body), "<html") ||
// 			strings.Contains(strings.ToLower(body), "<!doctype html")

// 		if isHTML {
// 			// Process HTML body
// 			htmlData := processHTMLBody(body)
// 			responseData["body"] = htmlData
// 		} else {
// 			// For non-HTML bodies, just include a truncated version
// 			if len(body) > 1000 {
// 				responseData["body"] = body[:1000] + "... (truncated)"
// 			} else {
// 				responseData["body"] = body
// 			}
// 		}
// 	}

// 	// Add metadata field for policy detection
// 	responseData["metadata"] = "HTTP_RESPONSE_JSON_FORMAT"

// 	// Convert to JSON string
// 	jsonBytes, err := json.Marshal(responseData)
// 	if err != nil {
// 		// If there's an error, return a simple JSON with error message
// 		return "{\"error\":\"Failed to process HTTP response\", \"metadata\":\"HTTP_RESPONSE_JSON_FORMAT\"}"
// 	}

// 	return string(jsonBytes)
// }

// // processHTMLBody extracts relevant information from HTML content
// func processHTMLBody(htmlContent string) map[string]interface{} {
// 	htmlData := make(map[string]interface{})

// 	// Extract title
// 	titleStart := strings.Index(strings.ToLower(htmlContent), "<title>")
// 	titleEnd := strings.Index(strings.ToLower(htmlContent), "</title>")
// 	if titleStart >= 0 && titleEnd > titleStart {
// 		htmlData["title"] = htmlContent[titleStart+7 : titleEnd]
// 	} else {
// 		htmlData["title"] = "Unknown Title"
// 	}

// 	// Extract basic text content (a simplified approach)
// 	cleanText := removeHTMLTags(htmlContent)

// 	// Truncate if too long
// 	if len(cleanText) > 1000 {
// 		cleanText = cleanText[:1000] + "... (truncated)"
// 	}

// 	// Remove extra whitespace
// 	cleanText = strings.TrimSpace(cleanText)
// 	cleanText = strings.Join(strings.Fields(cleanText), " ")

// 	htmlData["text"] = cleanText

// 	return htmlData
// }

// // removeHTMLTags removes HTML tags from the content
// func removeHTMLTags(content string) string {
// 	result := &strings.Builder{}
// 	inTag := false

// 	for _, r := range content {
// 		switch {
// 		case r == '<':
// 			inTag = true
// 		case r == '>':
// 			inTag = false
// 		case !inTag:
// 			result.WriteRune(r)
// 		}
// 	}

// 	return result.String()
// }

func (r *RequestTLS) Call(hsOnly bool) (RequestData, error) {

	// tls configs
	config := &tls.Config{
		InsecureSkipVerify:       false,
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: false,
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
		},
		ServerName: r.ServerDomain,
	}

	// local server testing settings
	if r.ServerDomain == "localhost" {
		PathCaCrt := "../certs/certificates/ca.crt"

		// set up cert verification
		caCert, _ := os.ReadFile(PathCaCrt)
		caCertPool, _ := x509.SystemCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		config.RootCAs = caCertPool

		r.ServerDomain += ":8081"
	}

	// measure start time
	start := time.Now()

	// tls connection
	conn, err := tls.Dial("tcp", r.ProxyURL, config)
	if err != nil {
		log.Error().Err(err).Msg("tls.Dial()")
		return RequestData{}, err
	}
	defer conn.Close()

	// tls handshake time
	elapsed := time.Since(start)
	log.Debug().Str("time", elapsed.String()).Msg("client tls handshake took.")
	// state := conn.ConnectionState()

	// return here if handshakeOnly flag set
	if hsOnly {
		return RequestData{}, nil
	}

	// server settings
	serverURL := "https://" + r.ServerDomain + r.ServerPath
	if r.UrlPrivateParts != "" {
		serverURL += r.UrlPrivateParts
	}

	// measure request-response roundtrip
	start = time.Now()

	// build request
	request, _ := http.NewRequest(http.MethodGet, serverURL, nil)
	request.Close = false

	// request headers
	request.Header.Set("Content-Type", "application/json")
	if r.AccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+r.AccessToken)
	}

	// initialize connection buffers
	bufr := bufio.NewReader(conn)
	bufw := bufio.NewWriter(conn)

	// write request to connection buffer
	err = request.Write(bufw)
	if err != nil {
		log.Error().Err(err).Msg("request.Write(bufw)")
		return RequestData{}, err
	}

	// writes buffer data into connection io.Writer
	err = bufw.Flush()
	if err != nil {
		log.Error().Err(err).Msg("bufw.Flush()")
		return RequestData{}, err
	}

	// read response
	resp, err := http.ReadResponse(bufr, request)
	if err != nil {
		log.Error().Err(err).Msg("http.ReadResponse(bufr, request)")
		return RequestData{}, err
	}
	defer resp.Body.Close()

	// reads response body
	msg, _ := io.ReadAll(resp.Body)
	log.Info().Msg("response data:")
	log.Info().Msg(string(msg))

	// catch time
	elapsed = time.Since(start)
	log.Debug().Str("time", elapsed.String()).Msg("client request-response roundtrip took.")

	// access to recorded session data
	return RequestData{
		secrets:   conn.GetSecretMap(),
		recordMap: conn.GetRecordMap(),
	}, nil
}

func (r *RequestTLS) Call2(hsOnly bool) (RequestData, error) {

	// tls configs
	config := &tls.Config{
		InsecureSkipVerify:       false,
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: false,
		// MinVersion:               tls.VersionTLS13,
		// MaxVersion:               tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		// ServerName: r.ServerDomain,
	}

	// local server testing settings
	if r.ServerDomain == "localhost" {
		PathCaCrt := "../certs/certificates/ca.crt"

		// set up cert verification
		caCert, _ := os.ReadFile(PathCaCrt)
		caCertPool, _ := x509.SystemCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		config.RootCAs = caCertPool

		r.ServerDomain += ":8081"
	}

	// measure start time
	start := time.Now()

	// tls connection
	conn, err := tls.Dial("tcp", "localhost:8081", config)
	if err != nil {
		log.Error().Err(err).Msg("tls.Dial()")
		return RequestData{}, err
	}
	defer conn.Close()

	// tls handshake time
	elapsed := time.Since(start)
	log.Debug().Str("time", elapsed.String()).Msg("client tls handshake took.")
	// state := conn.ConnectionState()

	// return here if handshakeOnly flag set
	if hsOnly {
		return RequestData{}, nil
	}

	// server settings
	serverURL := "https://" + r.ServerDomain + r.ServerPath
	if r.UrlPrivateParts != "" {
		serverURL += r.UrlPrivateParts
	}

	// measure request-response roundtrip
	start = time.Now()

	// build request
	request, _ := http.NewRequest(http.MethodGet, serverURL, nil)
	request.Close = false

	// request headers
	request.Header.Set("Content-Type", "application/json")
	if r.AccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+r.AccessToken)
	}

	// initialize connection buffers
	bufr := bufio.NewReader(conn)
	bufw := bufio.NewWriter(conn)

	// write request to connection buffer
	err = request.Write(bufw)
	if err != nil {
		log.Error().Err(err).Msg("request.Write(bufw)")
		return RequestData{}, err
	}

	// writes buffer data into connection io.Writer
	err = bufw.Flush()
	if err != nil {
		log.Error().Err(err).Msg("bufw.Flush()")
		return RequestData{}, err
	}

	// read response
	resp, err := http.ReadResponse(bufr, request)
	if err != nil {
		log.Error().Err(err).Msg("http.ReadResponse(bufr, request)")
		return RequestData{}, err
	}
	defer resp.Body.Close()

	// reads response body
	msg, _ := io.ReadAll(resp.Body)
	log.Info().Msg("response data:")
	log.Info().Msg(string(msg))
	sizeStr := strconv.Itoa(len(msg))
	log.Info().Msg(sizeStr)

	// catch time
	elapsed = time.Since(start)
	log.Debug().Str("time", elapsed.String()).Msg("client request-response roundtrip took.")

	// access to recorded session data
	return RequestData{
		secrets:   conn.GetSecretMap(),
		recordMap: conn.GetRecordMap(),
	}, nil
}
