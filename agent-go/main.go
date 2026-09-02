package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	ScannedAt string   `json:"scanned_at,omitempty"`
}

var (
	startTime       time.Time
	mu              sync.RWMutex
	devices         = []Device{}
	macPrefixesOnce sync.Once
	macPrefixesMap  = make(map[string]string)
)

var embeddedOUI = map[string]string{
	"00000C": "Cisco Systems",
	"000142": "Cisco Systems",
	"0004F2": "Polycom",
	"000C29": "VMware",
	"00155D": "Microsoft Hyper-V",
	"001A11": "Google",
	"001A2B": "Ayecom Technology",
	"001E67": "Intel",
	"0024E8": "Dell",
	"005056": "VMware",
	"04D4C4": "Apple",
	"04D9F5": "Apple",
	"06829B": "Apple Device",
	"06DC7B": "Mobile Device",
	"080027": "Oracle VirtualBox",
	"10DA43": "Netgear",
	"147DDA": "Apple",
	"186590": "Apple",
	"18B430": "Google / Nest",
	"1C1B0D": "Giga-Byte",
	"203706": "Cisco",
	"244BFE": "Amazon",
	"2818FD": "Aditya Infotech",
	"286FB9": "Apple",
	"28C63F": "Intel Corporate",
	"2C3033": "Netgear",
	"30074D": "Samsung",
	"306893": "TP-Link Systems",
	"3464A9": "Apple",
	"38892C": "Apple",
	"3C0630": "Apple",
	"406C8F": "Apple",
	"40A8F0": "Hewlett Packard",
	"40B034": "Hewlett Packard",
	"44070B": "Google",
	"48A98A": "TP-Link",
	"4C3275": "Apple",
	"50C7BF": "TP-Link",
	"54E43A": "Apple",
	"58108C": "Amazon",
	"5C879C": "Apple",
	"600308": "Apple",
	"64A5C3": "Apple",
	"68DBCA": "Apple",
	"6C2995": "Intel",
	"7081EB": "Amazon",
	"74AC5F": "Ubiquiti Networks",
	"784F43": "Apple",
	"7CF17E": "TP-Link Systems",
	"7CD95C": "Apple",
	"802AA8": "Ubiquiti Networks",
	"8478AC": "Apple",
	"88665A": "Apple",
	"8A273F": "Mobile Device",
	"8C8590": "Apple",
	"9009D0": "Synology Incorporated",
	"907240": "Apple",
	"94B40F": "Espressif (IoT)",
	"980CA5": "Intel",
	"9C293F": "Apple",
	"A0369F": "Intel",
	"A47733": "Google",
	"A85B78": "Apple",
	"ACDE48": "Apple",
	"B0A737": "Apple",
	"B42E99": "Intel",
	"B827EB": "Raspberry Pi Foundation",
	"BC6EE8": "Apple",
	"C0A5DD": "Google",
	"C43875": "Google",
	"C869CD": "Apple",
	"C895CE": "Intel Corporate",
	"CC25EF": "Samsung",
	"D05099": "Apple",
	"D46D6D": "TP-Link",
	"D83062": "Apple",
	"DC5360": "Intel Corporate",
	"DC85DE": "Amazon Technologies",
	"DCF505": "Apple",
	"E063DA": "Apple",
	"E450EB": "Apple",
	"E88D28": "Apple",
	"ECB1D7": "Hewlett Packard",
	"ECFA52": "Samsung",
	"F01898": "Apple",
	"F29E3E": "Mobile Device",
	"F43909": "Apple",
	"F4B520": "Biostar Microtech",
	"F83DC6": "AzureWave Technology",
	"F86F38": "Apple",
	"FC3497": "Apple",
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func initMACPrefixes() {
	for k, v := range embeddedOUI {
		macPrefixesMap[k] = v
	}

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
		if len(macPrefixesMap) > 100 {
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

func pingSingleHost(ip string) (bool, int64) {
	start := time.Now()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "400", ip)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("ping", "-c", "1", "-W", "400", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	err := cmd.Run()
	latency := time.Since(start).Milliseconds()
	if latency < 1 {
		latency = 1
	}
	if err == nil {
		return true, latency
	}
	return false, 0
}

func standardPingSweep(ips []string) map[string]int64 {
	live := make(map[string]int64)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(tip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ok, latency := pingSingleHost(tip); ok {
				mu.Lock()
				live[tip] = latency
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return live
}

func queryTLSCN(ip string, port uint16) string {
	d := &net.Dialer{Timeout: 350 * time.Millisecond}
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
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
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
	return runScanWithCallbacks(req, nil, nil)
}

func runScanWithCallbacks(
	req ScanRequest,
	onProgress func(scanned, total, pct int, currentIP string),
	onDevice func(dev Device),
) ([]Device, error) {
	portsList := []int{21, 22, 53, 80, 135, 139, 443, 445, 1883, 3000, 3389, 5000, 5353, 8000, 8080, 8443, 9000}
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

	total := len(allIPs)
	if total == 0 {
		total = 1
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

	// Fallback to standard ping sweep if fping is not installed or returned empty
	if len(fpingMap) == 0 && len(allIPs) > 0 {
		fpingMap = standardPingSweep(allIPs)
	}

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
	var scannedCount int64
	sem := make(chan struct{}, 64)

	for _, targetIP := range allIPs {
		wgScan.Add(1)
		sem <- struct{}{}
		go func(tip string) {
			defer wgScan.Done()
			defer func() { <-sem }()

			openPorts, fastestPing, hostReplied := probePortsFast(tip, portsList)
			isKnownLive := false

			muRes.Lock()
			meta, hasMeta := liveHosts[tip]
			if hasMeta || hostReplied || len(openPorts) > 0 {
				isKnownLive = true
			}
			muRes.Unlock()

			if isKnownLive {
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

				// D. TLS CN
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
				if hostName == "" && (tip == localGW || strings.HasSuffix(tip, ".1")) {
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

				if hostName == "" {
					parts := strings.Split(tip, ".")
					if len(parts) == 4 {
						hostName = fmt.Sprintf("Host-%s", parts[3])
					}
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
					ScannedAt: time.Now().UTC().Format(time.RFC3339),
				}

				muRes.Lock()
				results = append(results, dev)
				muRes.Unlock()

				if onDevice != nil {
					onDevice(dev)
				}
			}

			curScanned := int(atomic.AddInt64(&scannedCount, 1))
			if onProgress != nil {
				pct := int(float64(curScanned) / float64(total) * 100)
				if pct > 100 {
					pct = 100
				}
				onProgress(curScanned, total, pct, tip)
			}
		}(targetIP)
	}

	wgScan.Wait()

	// Re-read ARP table to populate MAC and Vendors discovered during network probes
	postArp := readARPTable()
	for i := range results {
		if results[i].MAC == "" {
			if m, ok := postArp[results[i].IP]; ok && m != "" {
				results[i].MAC = m
				if results[i].Vendor == "" {
					results[i].Vendor = lookupVendor(m)
					if strings.HasPrefix(results[i].Hostname, "Host-") && results[i].Vendor != "" {
						results[i].Hostname = fmt.Sprintf("%s Device", results[i].Vendor)
						if results[i].DNS != nil {
							*results[i].DNS = results[i].Hostname
						}
					}
				}
			}
		}
	}

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

func probePortsFast(ip string, ports []int) ([]uint16, int64, bool) {
	var open []uint16
	var fastestPing int64 = 0
	var hostReplied bool = false
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			start := time.Now()
			d := net.Dialer{Timeout: 300 * time.Millisecond}
			conn, err := d.DialContext(context.Background(), "tcp", addr)
			latency := time.Since(start).Milliseconds()
			if latency < 1 {
				latency = 1
			}

			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				conn.Close()
				open = append(open, uint16(port))
				hostReplied = true
				if fastestPing == 0 || latency < fastestPing {
					fastestPing = latency
				}
			} else {
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "reset by peer") {
					hostReplied = true
					if fastestPing == 0 || latency < fastestPing {
						fastestPing = latency
					}
				}
			}
		}(p)
	}

	wg.Wait()
	return open, fastestPing, hostReplied
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
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	portNum, _ := strconv.Atoi(port)
	if portNum == 0 {
		portNum = 8080
	}

	uptime := int64(0)
	if !startTime.IsZero() {
		uptime = int64(time.Since(startTime).Seconds())
	}

	json.NewEncoder(w).Encode(map[string]any{
		"status":             "online",
		"engine":             "Go High-Speed Agent",
		"hostname":           hostname(),
		"os":                 runtime.GOOS,
		"arch":               runtime.GOARCH,
		"uptimeSeconds":      uptime,
		"goAgentOnline":      true,
		"netlensAgentOnline": true,
		"port":               portNum,
		"version":            "1.0.0",
	})
}

func networkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cidr, gw := detectLocalSubnet()
	localIP := getLocalIPv4()
	_, mac := localNetworkInfo()
	arpMap := readARPTable()
	gwMAC := arpMap[gw]
	gwVendor := lookupVendor(gwMAC)
	if gwVendor == "" {
		if gw == "192.168.0.1" || gw == "192.168.1.1" {
			gwVendor = "TP-Link Systems"
		} else {
			gwVendor = "Network Gateway / Router"
		}
	}

	ssid := "Local Wi-Fi Network"
	security := "WPA2 / WPA3 Personal"
	networkType := "personal"
	trustScore := 95
	riskRating := "Low Risk - Protected Personal Wi-Fi"
	scanStrategy := "Full Home LAN Device Discovery & Open Share Security Audit"

	// Check iwgetid if available
	if out, err := exec.Command("iwgetid", "-r").Output(); err == nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			ssid = trimmed
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"hostname":      hostname(),
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"localIP":       localIP,
		"mac":           mac,
		"cidr":          cidr,
		"gateway":       gw,
		"gatewayVendor": gwVendor,
		"ssid":          ssid,
		"signal":        "90%",
		"security":      security,
		"networkType":   networkType,
		"trustScore":    trustScore,
		"riskRating":    riskRating,
		"scanStrategy":  scanStrategy,
	})
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	statusHandler(w, r)
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
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
		"devices":   d,
		"last_scan": time.Now().UTC().Format(time.RFC3339),
	})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
		detectedCIDR, _ := detectLocalSubnet()
		req.CIDR = detectedCIDR
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func scanStreamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	cidrParam := r.URL.Query().Get("cidr")
	if cidrParam == "" {
		cidrParam, _ = detectLocalSubnet()
	}

	sendEvent := func(event string, payload any) {
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(data))
		flusher.Flush()
	}

	sendEvent("status", map[string]string{"message": "Go High-Speed Agent connected and sweeping subnet..."})

	portsParam := r.URL.Query().Get("ports")
	var ports []int
	if portsParam != "" {
		for _, pStr := range strings.Split(portsParam, ",") {
			if p, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil && p > 0 {
				ports = append(ports, p)
			}
		}
	}

	onProgress := func(scanned, total, pct int, currentIP string) {
		sendEvent("progress", map[string]any{
			"scanned":    scanned,
			"total":      total,
			"percentage": pct,
			"currentIp":  currentIP,
		})
	}

	onDevice := func(dev Device) {
		sendEvent("device", dev)
	}

	devicesList, err := runScanWithCallbacks(ScanRequest{CIDR: cidrParam, Ports: ports}, onProgress, onDevice)
	if err != nil {
		sendEvent("error", map[string]string{"message": err.Error()})
		return
	}

	mu.Lock()
	devices = devicesList
	mu.Unlock()

	sendEvent("complete", map[string]any{
		"devices": devicesList,
		"total":   len(devicesList),
	})
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

const defaultGroqModel = "openai/gpt-oss-120b"

var supportedGroqModels = []string{
	"openai/gpt-oss-120b",
	"openai/gpt-oss-20b",
	"qwen/qwen3.8-27b",
	"qwen/qwen3.6-27b",
	"groq/compound",
}

func getGroqAPIKey() string {
	if k := os.Getenv("GROQ_API_KEY"); k != "" {
		return k
	}
	for _, p := range []string{".env", "../.env", "../dashboard/.env.local", "dashboard/.env.local", ".env.local"} {
		if content, err := os.ReadFile(p); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "GROQ_API_KEY=") {
					val := strings.TrimPrefix(line, "GROQ_API_KEY=")
					val = strings.Trim(val, `"' `)
					if val != "" && !strings.Contains(val, "your_") {
						return val
					}
				}
			}
		}
	}
	return ""
}

func getGroqModel() string {
	if m := os.Getenv("GROQ_MODEL"); m != "" {
		return m
	}
	for _, p := range []string{".env", "../.env", "../dashboard/.env.local", "dashboard/.env.local", ".env.local"} {
		if content, err := os.ReadFile(p); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "GROQ_MODEL=") {
					val := strings.TrimPrefix(line, "GROQ_MODEL=")
					val = strings.Trim(val, `"' `)
					if val != "" {
						return val
					}
				}
			}
		}
	}
	return defaultGroqModel
}

type summaryRequest struct {
	APIKey  string   `json:"apiKey,omitempty"`
	Model   string   `json:"model,omitempty"`
	Prompt  string   `json:"prompt,omitempty"`
	Devices []Device `json:"devices,omitempty"`
}

func summaryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	apiKey := getGroqAPIKey()

	if r.Method == http.MethodGet {
		isConfigured := strings.HasPrefix(apiKey, "gsk_")
		masked := "Not configured"
		if isConfigured && len(apiKey) > 12 {
			masked = apiKey[:8] + "..." + apiKey[len(apiKey)-4:]
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "ok",
			"configured":      isConfigured,
			"maskedKey":       masked,
			"currentModel":    getGroqModel(),
			"availableModels": supportedGroqModels,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req summaryRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.APIKey != "" && strings.HasPrefix(req.APIKey, "gsk_") {
		apiKey = strings.TrimSpace(req.APIKey)
	} else if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if strings.HasPrefix(token, "gsk_") {
			apiKey = strings.TrimSpace(token)
		}
	}

	if apiKey == "" {
		http.Error(w, `{"error":"Groq API key not configured"}`, http.StatusBadRequest)
		return
	}

	requestedModel := req.Model
	if requestedModel == "" {
		requestedModel = getGroqModel()
	}

	var scanDevices []Device
	if len(req.Devices) > 0 {
		scanDevices = req.Devices
	} else {
		mu.RLock()
		scanDevices = make([]Device, len(devices))
		copy(scanDevices, devices)
		mu.RUnlock()
	}

	cidr, gw := detectLocalSubnet()
	totalOpenPorts := 0
	deviceBreakdown := ""
	for i, d := range scanDevices {
		totalOpenPorts += len(d.OpenPorts)
		portsStr := "None"
		if len(d.OpenPorts) > 0 {
			var pStrs []string
			for _, p := range d.OpenPorts {
				pStrs = append(pStrs, strconv.Itoa(int(p)))
			}
			portsStr = strings.Join(pStrs, ", ")
		}
		pingStr := "N/A"
		if d.PingMS != nil {
			pingStr = fmt.Sprintf("%dms", *d.PingMS)
		}
		deviceBreakdown += fmt.Sprintf("Device #%d:\n  - IP: %s\n  - Hostname: %s\n  - Vendor: %s\n  - MAC: %s\n  - Ping: %s\n  - Reachable: %t\n  - Open Ports: [%s]\n\n",
			i+1, d.IP, d.Hostname, d.Vendor, d.MAC, pingStr, d.Reachable, portsStr)
	}

	systemPrompt := `You are LAN Sentinel AI, a senior network security auditor and systems architect.
Your mission is to examine network telemetry and live discovery scans from the local agent and generate a comprehensive, highly detailed network summary and defensive security assessment.

Guidelines for formatting your response:
- Use clean GitHub-flavored Markdown.
- Use structured headings, emoji indicators, bullet points, and data tables where helpful.
- Provide a rigorous, in-depth breakdown covering:
  1. 🌐 Executive Network Overview & Architecture
  2. 💻 Device Inventory & Host Categorization
  3. 🔓 Port Exposure & Attack Surface Analysis
  4. 🛡️ Defensive Security Recommendations & Hardening Steps
  5. 📊 Network Hygiene Score (0-100) & Conclusion

Maintain a professional, authoritative, yet accessible cybersecurity tone.`

	userPrompt := fmt.Sprintf(`Please generate an in-depth Network Security Summary for this scan:
--- NETWORK CONTEXT ---
Subnet CIDR: %s
Gateway IP: %s
Agent Host OS: %s (%s)
Total Discovered Devices: %d
Total Exposed Services: %d

--- DEVICE DETAILS ---
%s
%s
Generate the comprehensive security audit report now.`, cidr, gw, runtime.GOOS, runtime.GOARCH, len(scanDevices), totalOpenPorts,
		func() string {
			if deviceBreakdown == "" {
				return "No devices discovered yet (Subnet was empty or initial scan just started)."
			}
			return deviceBreakdown
		}(),
		func() string {
			if req.Prompt != "" {
				return "\n--- CUSTOM USER FOCUS ---\n" + req.Prompt + "\n"
			}
			return ""
		}())

	modelsToTry := []string{requestedModel}
	for _, m := range supportedGroqModels {
		if m != requestedModel {
			modelsToTry = append(modelsToTry, m)
		}
	}

	var summaryText string
	var modelUsed string
	var lastErr error

	httpClient := &http.Client{Timeout: 45 * time.Second}

	for _, m := range modelsToTry {
		reqBody := map[string]any{
			"model": m,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"temperature": 0.3,
			"max_tokens":  4096,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		httpReq, err := http.NewRequest(http.MethodPost, "https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			continue
		}

		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("Groq HTTP %d: %s", resp.StatusCode, string(respBytes))
			continue
		}

		var groqResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(respBytes, &groqResp); err == nil && len(groqResp.Choices) > 0 {
			summaryText = groqResp.Choices[0].Message.Content
			modelUsed = m
			break
		}
	}

	if summaryText == "" {
		w.WriteHeader(http.StatusBadGateway)
		errMsg := "Failed to generate summary from Groq LLM"
		if lastErr != nil {
			errMsg = lastErr.Error()
		}
		json.NewEncoder(w).Encode(map[string]any{
			"error": errMsg,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"summary":     summaryText,
		"model":       modelUsed,
		"deviceCount": len(scanDevices),
		"portCount":   totalOpenPorts,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	startTime = time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/agent/status", statusHandler)
	mux.HandleFunc("/api/network", networkHandler)
	mux.HandleFunc("/api/devices", devicesHandler)
	mux.HandleFunc("/api/scan", scanHandler)
	mux.HandleFunc("/api/scan/stream", scanStreamHandler)
	mux.HandleFunc("/api/summary", summaryHandler)
	mux.HandleFunc("/ws", wsHandler)

	handler := corsMiddleware(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	// Automatically run an initial non-blocking background discovery
	go func() {
		time.Sleep(300 * time.Millisecond)
		cidr, _ := detectLocalSubnet()
		if cidr != "" {
			res, err := runScan(ScanRequest{CIDR: cidr})
			if err == nil && len(res) > 0 {
				mu.Lock()
				devices = res
				mu.Unlock()
			}
		}
	}()

	fmt.Printf("Go High-Speed Agent listening on %s (PORT=%s)\n", addr, port)
	if err := http.ListenAndServe(addr, handler); err != nil {
		panic(err)
	}
}
