package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Log file configuration
const logDir = "./logs"
const errorLogFile = logDir + "/errors.log"
const infoLogFile = logDir + "/info.log"

// Loggers
var errorLogger *log.Logger
var infoLogger *log.Logger

// Initialize logging
func init() {
	// Create log directory if it does not exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Error creating log directory: %v", err)
	}

	// Open error log file
	errorFile, err := os.OpenFile(errorLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating error log file: %v", err)
	}

	// Open info log file
	infoFile, err := os.OpenFile(infoLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating info log file: %v", err)
	}

	// Set up loggers
	errorLogger = log.New(errorFile, "[ERROR] ", log.LstdFlags)
	infoLogger = log.New(infoFile, "[INFO] ", log.LstdFlags)

	infoLogger.Println("🚀 Server is starting...")
}

const SlackWebhookURL = "SLACK_WEBHOOK_URL"

// Struct for the notification message
type SlackMessage struct {
	Text string `json:"text"`
}

// SendSlackNotification sends a message to Slack
func SendSlackNotification(name, email, phone string) error {
	// Construct message
	message := fmt.Sprintf("*New Form Submission!* 🎉\n👤 *Name:* %s\n📧 *Email:* %s\n📞 *Phone:* %s", name, email, phone)

	// Convert to JSON
	payload, err := json.Marshal(SlackMessage{Text: message})
	if err != nil {
		return fmt.Errorf("notifier: error encoding JSON: %v", err)
	}

	// Send HTTP POST request to Slack webhook
	resp, err := http.Post(SlackWebhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("notifier: error sending request to Slack: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("notifier: webhook request failed with status: %d", resp.StatusCode)
	}

	log.Println("✅ Slack notification sent successfully!")
	return nil
}

// Struct to store received data
type Lead struct {
	Name    string `json:"name"`
	Phone   string `json:"phone"`
	Email   string `json:"email"`
	Role    string `json:"role,omitempty"`
	Message string `json:"message,omitempty"`
}

// Rate Limiting (Prevents DoS attacks)
var rateLimiter = make(map[string]int)
var mu sync.Mutex

func isRateLimited(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := rateLimiter[ip]; !exists {
		rateLimiter[ip] = 1
		go func() {
			time.Sleep(1 * time.Minute) // Reset after 1 minute
			mu.Lock()
			delete(rateLimiter, ip)
			mu.Unlock()
		}()
		return false
	}

	if rateLimiter[ip] >= 5 {
		errorLogger.Printf("IP blocked: %s (excessive requests)", ip)
		fmt.Printf("IP blocked: %s (excessive requests)", ip)
		return true
	}

	rateLimiter[ip]++
	return false
}

// Save received data to leads.txt
func saveToFile(lead Lead) error {
	file, err := os.OpenFile("leads.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	entry := fmt.Sprintf("📌 [%s]\nName: %s\nPhone: %s\nEmail: %s\n",
		time.Now().Format("2006-01-02 15:04:05"), lead.Name, lead.Phone, lead.Email)

	if lead.Message != "" {
		entry += fmt.Sprintf("Message: %s\n", lead.Message)
	}

	if lead.Role != "" {
		entry += fmt.Sprintf("Role: %s\n", lead.Role)
	}

	entry += "----------------------\n"
	_, err = file.WriteString(entry)

	if err == nil {
		infoLogger.Printf("Lead saved: %s, %s", lead.Name, lead.Email)
	}

	return err
}

// CSRF Protection Middleware
func csrfProtection(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowedOrigins := map[string]bool{
			"http://localhost":           true,
			"http://localhost:3000":      true,
			"https://markado.com.br":     true,
			"https://www.markado.com.br": true,
		}

		origin := r.Header.Get("Origin")
		fmt.Println(">>>>> origin <<<<<<<", origin)

		if origin != "" && !allowedOrigins[origin] {
			http.Error(w, "CSRF attempt detected", http.StatusForbidden)
			errorLogger.Printf("CSRF attempt blocked. Origin: %s", origin)
			fmt.Printf("CSRF attempt blocked. Origin: %s", origin)
			return
		}

		next(w, r)
	}
}

// Handler to process form submissions
func handleSubmission(w http.ResponseWriter, r *http.Request) {
	// enableCORS(w, r)
	infoLogger.Println("Request received", r.Method, r.RemoteAddr)

	headers := r.Header
	for key, value := range headers {
		fmt.Printf("%s: %s\n", key, value)
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = "unknown"
	}

	if isRateLimited(ip) {
		http.Error(w, "Too many requests, please try again later", http.StatusTooManyRequests)
		fmt.Printf("Rate limit exceeded for IP: %s", ip)
		errorLogger.Printf("Rate limit exceeded for IP: %s", ip)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024) // Limit request body size to 1KB

	var lead Lead
	err = json.NewDecoder(r.Body).Decode(&lead)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		fmt.Printf("Invalid JSON received from %s", ip)
		errorLogger.Printf("Invalid JSON received from %v", err)
		return
	}

	if !isValidInput(lead.Name) || !isValidInput(lead.Email) {
		http.Error(w, "Invalid data detected!", http.StatusBadRequest)
		fmt.Printf("Malicious input blocked from %s", ip)
		errorLogger.Printf("Malicious input blocked from %s", ip)
		return
	}

	err = saveToFile(lead)
	if err != nil {
		http.Error(w, "Error saving data", http.StatusInternalServerError)
		errorLogger.Printf("Failed to save lead from %v", err)
		fmt.Printf("Failed to save lead from %s", err)
		return
	}

	go SendSlackNotification(lead.Name, lead.Email, lead.Phone)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Lead successfully received!"))
}

// Validate input and prevent code injection
func isValidInput(input string) bool {
	if strings.ContainsAny(input, "<>{}[]()'\";:") {
		return false
	}
	if len(input) > 100 {
		return false
	}
	return true
}

// func enableCORS(w http.ResponseWriter, r *http.Request) {
// 	allowedOrigins := map[string]bool{
// 		"http://localhost":           true,
// 		"http://localhost:3000":      true,
// 		"https://www.markado.com.br": true,
// 		"https://markado.com.br":     true,
// 	}

// 	origin := r.Header.Get("Origin")

// 	if allowedOrigins[origin] {
// 		fmt.Println(">>>>>> allowed origin <<<<<<")
// 		w.Header().Set("Access-Control-Allow-Origin", origin)
// 		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
// 		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
// 		w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type") // ✅ Expose headers to frontend
// 		w.Header().Set("Access-Control-Allow-Credentials", "true")                      // Needed for cookies/auth
// 		w.Header().Set("Vary", "Origin")                                                // Important for caching
// 	}
// }

func main() {
	mux := http.NewServeMux()

	// Single endpoint for all submissions
	mux.HandleFunc("/form/submit", csrfProtection(handleSubmission))

	server := &http.Server{
		Addr:           ":4001",
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1024,
	}

	fmt.Println("🚀 Secure server running at http://localhost:4001")
	infoLogger.Println("🚀 Secure server running at http://localhost:4001")
	log.Fatal(server.ListenAndServe())
}
