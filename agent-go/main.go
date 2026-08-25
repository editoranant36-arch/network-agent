package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type ScanRequest struct {
	CIDR  string `json:"cidr"`
	Ports []int  `json:"ports"`
}

type Device struct {
	IP        string   `json:"ip"`
	Hostname  string   `json:"hostname,omitempty"`
	DNS       *string  `json:"dns,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Reachable bool     `json:"reachable"`
	PingMS    *int64   `json:"ping_ms"`
	OpenPorts []uint16 `json:"open_ports"`
	MAC       string   `json:"mac,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
}

var (
	mu              sync.RWMutex
	devices         = []Device{}
	macPrefixesOnce sync.Once
	macPrefixesMap  = make(map[string]string)
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func initMACPrefixes() {
	paths := []string{
		"/usr/share/nmap/nmap-mac-prefixes",
		"/usr/share/wireshark/manuf",
		"/usr/share/ieee-data/oui.txt",
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && len(fields[0]) == 6 {
				prefix := strings.ToUpper(fields[0])
				vendor := strings.Join(fields[1:], " ")
				macPrefixesMap[prefix] = vendor
			}
		}
		if len(macPrefixesMap) > 0 {
			break
		}
	}
}

func lookupVendor(mac string) string {
	macPrefixesOnce.Do(initMACPrefixes)
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
	if len(clean) >= 6 {
		prefix := clean[:6]
		if v, ok := macPrefixesMap[prefix]; ok {
			return v
		}
	}
	return ""
}

type NetBIOSInfo struct {
	Name string
	MAC  string
}

func scanNetBIOS(cidr string) map[string]NetBIOSInfo {
	res := make(map[string]NetBIOSInfo)
	cmd := exec.Command("nbtscan", "-q", "-s", ":", cidr)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()

	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			ip := strings.TrimSpace(parts[0])
			name := strings.TrimSpace(parts[1])
			mac := ""
			if len(parts) >= 5 {
				mac = strings.ToLower(strings.TrimSpace(strings.Join(parts[4:], ":")))
				if strings.Contains(mac, "00:00:00:00:00:00") {
					mac = ""
				}
			}
			if ip != "" && name != "" {
				res[ip] = NetBIOSInfo{Name: name, MAC: mac}
			}
		}
	}
	return res
}

func readARPTable() map[string]string {
	arpMap := make(map[string]string)
	if b, err := os.ReadFile("/proc/net/arp"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ip := fields[0]
				mac := fields[3]
				if mac != "00:00:00:00:00:00" && !strings.Contains(ip, "IP") {
					arpMap[ip] = mac
				}
			}
		}
	}
	return arpMap
}

func fpingSweep(cidr string) map[string]int64 {
	live := make(map[string]int64)
	cmd := exec.Command("fping", "-a", "-e", "-q", "-g", cidr)
	out, err := cmd.CombinedOutput()
	if err == nil || len(out) > 0 {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				ip := fields[0]
				ms := int64(15)
				if len(fields) >= 2 {
					// e.g. "(12.4 ms)"
					raw := strings.Trim(fields[1], "()ms ")
					if val, parseErr := strconv.ParseFloat(raw, 64); parseErr == nil {
						ms = int64(val)
					}
				}
				live[ip] = ms
			}
		}
	}
	return live
}

func queryTLSCN(ip string, port uint16) string {
	d := &net.Dialer{Timeout: 400 * time.Millisecond}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cn := certs[0].Subject.CommonName
		if cn != "" {
			return cn
		}
		if len(certs[0].DNSNames) > 0 {
			return certs[0].DNSNames[0]
		}
	}
	return ""
}

func reverseDNS(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	var r net.Resolver
	names, err := r.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		if name != "" && !strings.Contains(name, "in-addr.arpa") {
			return name
		}
	}
	return ""
}

func runScan(req ScanRequest) ([]Device, error) {
	portsList := []int{22, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443}
	if len(req.Ports) > 0 {
		portsList = req.Ports
	}

	ip, ipnet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// 1. Gather all potential host IPs in CIDR
	var allIPs []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		curCopy := make(net.IP, len(cur))
		copy(curCopy, cur)
		allIPs = append(allIPs, curCopy.String())
	}
	if len(allIPs) > 2 {
		allIPs = allIPs[1 : len(allIPs)-1] // exclude network and broadcast
	}

	localGW, localMAC := localNetworkInfo()
	localIP := getLocalIPv4()

	// 2. Discover live hosts in parallel
	var nbMap map[string]NetBIOSInfo
	var fpingMap map[string]int64
	var wgDisc sync.WaitGroup

	wgDisc.Add(2)
	go func() {
		defer wgDisc.Done()
		nbMap = scanNetBIOS(req.CIDR)
	}()
	go func() {
		defer wgDisc.Done()
		fpingMap = fpingSweep(req.CIDR)
	}()
	wgDisc.Wait()

	arpMap := readARPTable()

	// Seed live hosts map with initial discovery
	type hostMeta struct {
		pingMS int64
		mac    string
		nbName string
	}
	liveHosts := make(map[string]*hostMeta)

	for ipStr, ms := range fpingMap {
		liveHosts[ipStr] = &hostMeta{pingMS: ms}
	}
	for ipStr, nb := range nbMap {
		if meta, exists := liveHosts[ipStr]; exists {
			meta.nbName = nb.Name
			if nb.MAC != "" {
				meta.mac = nb.MAC
			}
		} else {
			liveHosts[ipStr] = &hostMeta{pingMS: 20, nbName: nb.Name, mac: nb.MAC}
		}
	}
	for ipStr, mac := range arpMap {
		if ipnet.Contains(net.ParseIP(ipStr)) {
			if meta, exists := liveHosts[ipStr]; exists {
				if meta.mac == "" {
					meta.mac = mac
				}
			} else {
				liveHosts[ipStr] = &hostMeta{pingMS: 25, mac: mac}
			}
		}
	}

	// Always ensure Gateway and Local IP are tested
	if localGW != "" && ipnet.Contains(net.ParseIP(localGW)) {
		if _, exists := liveHosts[localGW]; !exists {
			liveHosts[localGW] = &hostMeta{pingMS: 10}
		}
	}
	if localIP != "" && ipnet.Contains(net.ParseIP(localIP)) {
		if _, exists := liveHosts[localIP]; !exists {
			liveHosts[localIP] = &hostMeta{pingMS: 1, mac: localMAC}
		}
	}

	// 3. Scan TCP ports & discover responsive hosts across entire CIDR
	var muRes sync.Mutex
	var results []Device
	var wgScan sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, targetIP := range allIPs {
		wgScan.Add(1)
		sem <- struct{}{}
		go func(tip string) {
			defer wgScan.Done()
			defer func() { <-sem }()

			openPorts, fastestPing := probePortsFast(tip, portsList)
			isKnownLive := false

			muRes.Lock()
			meta, hasMeta := liveHosts[tip]
			if hasMeta || len(openPorts) > 0 {
				isKnownLive = true
			}
			muRes.Unlock()

			if !isKnownLive {
				return
			}

			// Determine MAC address
			mac := ""
			if meta != nil && meta.mac != "" {
				mac = meta.mac
			}
			if mac == "" {
				if m, ok := arpMap[tip]; ok {
					mac = m
				}
			}
			if mac == "" && tip == localIP {
				mac = localMAC
			}

			vendor := lookupVendor(mac)

			// Determine Ping MS
			var pingMS int64 = 15
			if fastestPing > 0 {
				pingMS = fastestPing
			} else if meta != nil && meta.pingMS > 0 {
				pingMS = meta.pingMS
			}

			// Hostname Resolution Strategy
			var hostName string

			// A. Localhost check
			if tip == localIP || tip == "127.0.0.1" {
				h, _ := os.Hostname()
				if h != "" {
					hostName = fmt.Sprintf("%s (This Device)", h)
				}
			}

			// B. NetBIOS Name
			if hostName == "" && meta != nil && meta.nbName != "" {
				hostName = meta.nbName
			}

			// C. Reverse DNS PTR
			if hostName == "" {
				if ptr := reverseDNS(tip); ptr != "" {
					hostName = ptr
				}
			}

			// D. TLS CN (e.g. router web portal or server cert)
			if hostName == "" {
				for _, p := range openPorts {
					if p == 443 || p == 8443 {
						if cn := queryTLSCN(tip, p); cn != "" {
							hostName = cn
							break
						}
					}
				}
			}

			// E. Gateway identity
			if hostName == "" && tip == localGW {
				if vendor != "" {
					hostName = fmt.Sprintf("Gateway / Router (%s)", vendor)
				} else {
					hostName = "Default Gateway / Router"
				}
			}

			// F. Known Vendor Device identity
			if hostName == "" && vendor != "" {
				hostName = fmt.Sprintf("%s Device", vendor)
			}

			var dnsPtr *string
			if hostName != "" {
				dnsPtr = &hostName
			}

			if openPorts == nil {
				openPorts = []uint16{}
			}

			dev := Device{
				IP:        tip,
				Hostname:  hostName,
				DNS:       dnsPtr,
				Vendor:    vendor,
				Reachable: true,
				PingMS:    &pingMS,
				OpenPorts: openPorts,
				MAC:       mac,
				Gateway:   localGW,
			}

			muRes.Lock()
			results = append(results, dev)
			muRes.Unlock()
		}(targetIP)
	}

	wgScan.Wait()

	// Sort numerically by IP
	sort.Slice(results, func(i, j int) bool {
		ip1 := net.ParseIP(results[i].IP).To4()
		ip2 := net.ParseIP(results[j].IP).To4()
		if ip1 == nil || ip2 == nil {
			return results[i].IP < results[j].IP
		}
		return bytes.Compare(ip1, ip2) < 0
	})

	if results == nil {
		results = []Device{}
	}
	return results, nil
}

func probePortsFast(ip string, ports []int) ([]uint16, int64) {
	var open []uint16
	var fastestPing int64 = 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			start := time.Now()
			d := net.Dialer{Timeout: 350 * time.Millisecond}
			conn, err := d.DialContext(context.Background(), "tcp", addr)
			if err == nil {
				latency := time.Since(start).Milliseconds()
				conn.Close()
				mu.Lock()
				open = append(open, uint16(port))
				if fastestPing == 0 || latency < fastestPing {
					fastestPing = latency
				}
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	return open, fastestPing
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getLocalIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

func detectLocalSubnet() (string, string) {
	gw := defaultGatewayLinux()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "192.168.0.0/24", gw
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					mask := ipnet.Mask
					network := ip4.Mask(mask)
					ones, _ := mask.Size()
					cidr := fmt.Sprintf("%s/%d", network.String(), ones)
					return cidr, gw
				}
			}
		}
	}
	return "192.168.0.0/24", gw
}

func defaultGatewayLinux() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			var b0, b1, b2, b3 byte
			n, _ := fmt.Sscanf(fields[2], "%02X%02X%02X%02X", &b3, &b2, &b1, &b0)
			if n == 4 {
				return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
			}
		}
	}
	return ""
}

func localNetworkInfo() (gateway, mac string) {
	gateway = defaultGatewayLinux()
	ifaces, _ := net.Interfaces()
	for _, in := range ifaces {
		if in.Flags&net.FlagUp != 0 && in.Flags&net.FlagLoopback == 0 && len(in.HardwareAddr) > 0 {
			mac = in.HardwareAddr.String()
			break
		}
	}
	return gateway, mac
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func networkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	cidr, gw := detectLocalSubnet()
	_, mac := localNetworkInfo()
	json.NewEncoder(w).Encode(map[string]any{
		"hostname": hostname(),
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"cidr":     cidr,
		"gateway":  gw,
		"mac":      mac,
	})
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"agent":   "go",
		"version": "1.0.0",
	})
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	if r.Method == http.MethodDelete {
		mu.Lock()
		devices = []Device{}
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "Memory cleared"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()
	d := devices
	if d == nil {
		d = []Device{}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"devices": d,
	})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
		http.Error(w, "valid cidr required", http.StatusBadRequest)
		return
	}

	result, err := runScan(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result == nil {
		result = []Device{}
	}

	mu.Lock()
	devices = result
	mu.Unlock()

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()

	for {
		mu.RLock()
		d := devices
		if d == nil {
			d = []Device{}
		}
		payload, _ := json.Marshal(d)
		mu.RUnlock()
		if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/network", networkHandler)
	mux.HandleFunc("/api/devices", devicesHandler)
	mux.HandleFunc("/api/scan", scanHandler)
	mux.HandleFunc("/ws", wsHandler)

	handler := corsMiddleware(mux)

	fmt.Println("Go agent listening on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		panic(err)
	}
}


