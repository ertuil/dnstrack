package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"log/slog"

	"compress/gzip"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

const (
	TimeoutPeriod = 1 * time.Minute
)

var (
	fmtLogger      *slog.Logger
	zipWritter     *gzip.Writer
	zipWritterLock sync.Mutex = sync.Mutex{}

	dnsMatchMap = cache.NewCache[string, *DNSMatch]().WithMaxKeys(655360).WithTTL(TimeoutPeriod)

	optDebug  = flag.Bool("d", false, "enable debug logging")
	optIface  = flag.String("i", "eth0", "interface to capture from")
	optLog    = flag.String("l", "", "log file (default: dns)")
	optMaxDay = flag.Int("p", 30, "max days to keep log files")
)

func main() {
	flag.Parse()
	InitLogger()
	if *optIface == "" {
		fmtLogger.Error("No interface specified")
		os.Exit(1)
	}

	go AtExit()
	go FileLogRotateServe()
	Serve()
}

func InitLogger() {
	if *optDebug {
		fmtLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true}))
	} else {
		fmtLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	err := FileLogRotate()
	if err != nil {
		fmtLogger.Error("Could not open log file", slog.String("file", *optLog), slog.Any("error", err))
		os.Exit(1)
	}
}

func AtExit() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	fmtLogger.Info("Shutting down...")
	if zipWritter != nil {
		zipWritter.Close()
	}
	os.Exit(0)
}

func FileLogRotateServe() {
	// 每天0点开始轮询
	for {
		now := time.Now()
		next := now.Add(time.Hour * 24)
		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())

		t := time.NewTimer(next.Sub(now))
		<-t.C
		err := FileLogRotate()
		if err != nil {
			fmtLogger.Error("Could not rotate log file", slog.String("file", *optLog), slog.Any("error", err))
		}
	}
}

func FileLogRotate() (err error) {

	// 删除过期日志
	if *optLog != "" && *optMaxDay > 0 {

		fmtLogger.Info("Rotating log files", slog.String("prefix", *optLog), slog.Int("max_days", *optMaxDay))

		files, err := os.ReadDir(".")
		if err != nil {
			fmtLogger.Error("Could not read log directory", slog.Any("error", err))
			return err
		}

		expireTime := time.Now().Add(-time.Duration(*optMaxDay) * 24 * time.Hour)
		// expireTime := time.Now()
		for _, file := range files {
			if strings.HasPrefix(file.Name(), *optLog) && strings.HasSuffix(file.Name(), ".txt.gz") {
				if info, err := file.Info(); err == nil {
					if info.ModTime().Before(expireTime) {
						if err := os.Remove(file.Name()); err != nil {
							fmtLogger.Error("Could not remove log file", slog.String("file", file.Name()), slog.Any("error", err))
						} else {
							fmtLogger.Info("Removed expired log file", slog.String("file", file.Name()))
						}
					}
				}
			}
		}
	}

	if *optLog != "" {
		zipWritterLock.Lock()
		defer zipWritterLock.Unlock()
		now := time.Now()
		filename := fmt.Sprintf("%s-%s.txt.gz", *optLog, now.Format("2006-01-02"))
		fmtLogger.Info("Opening new log file", slog.String("filename", filename))

		file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}

		if zipWritter != nil {
			zipWritter.Close()
		}

		zipWritter = gzip.NewWriter(file)
		zipWritter.ModTime = now
		zipWritter.Name = filename
		zipWritter.Comment = "dns-track log file"
		zipWritter.Flush()
	}

	return nil
}

func Serve() {

	bpf_cmd := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 9},

		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 0, SkipFalse: 15},

		bpf.LoadAbsolute{Off: 20, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 13, SkipFalse: 0},

		bpf.LoadMemShift{Off: 14},

		bpf.LoadIndirect{Off: 14, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 9, SkipFalse: 0},

		bpf.LoadIndirect{Off: 16, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 7, SkipFalse: 8},

		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0, SkipFalse: 7},

		bpf.LoadAbsolute{Off: 20, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 0, SkipFalse: 5},

		bpf.LoadAbsolute{Off: 54, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 2, SkipFalse: 0},

		bpf.LoadAbsolute{Off: 56, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 0, SkipFalse: 1},

		bpf.RetConstant{Val: 262144},
		bpf.RetConstant{Val: 0},
	}

	bpfcmd, err := bpf.Assemble(bpf_cmd)
	if err != nil {
		fmtLogger.Error("Could not assemble BPF instructions", slog.Any("error", err))
		os.Exit(1)
	}

	fmtLogger.Info("Starting capture", slog.String("iface", *optIface), "code", bpfcmd)

	handle, err := pcapgo.NewEthernetHandle(*optIface)
	if err != nil {
		fmtLogger.Error("Could not open Ethernet handle", slog.Any("error", err))
		os.Exit(1)
	}
	handle.SetBPF(bpfcmd)
	handle.SetPromiscuous(true)
	handle.SetCaptureLength(262144)

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if stat, err := handle.Stats(); err == nil {
				fmtLogger.Info("Capture stats", "packets", stat.Packets, "dropped", stat.Drops)
			} else {
				fmtLogger.Error("Could not get capture stats", slog.Any("error", err))
			}
		}
	}()

	for {
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			fmtLogger.Error("Error reading packet data", slog.Any("error", err))
		}
		ts := ci.Timestamp
		ln := ci.Length
		if ln == 0 {
			continue
		}

		Handle(ts, data[:ln])
	}

	// 	if handle, err := pcap.OpenLive(*optIface, 1600, true, pcap.BlockForever); err != nil {
	// 		fmtLogger.Error("Could not open device", slog.String("device", *optIface), slog.Any("error", err))
	// 		os.Exit(1)
	// 	} else if err := handle.SetBPFFilter("udp and port 53"); err != nil { // optional
	// 		fmtLogger.Error("Could not set BPF filter", slog.String("filter", "udp and port 53"), slog.Any("error", err))
	// 		os.Exit(1)
	// 	} else {

	// 		for {
	// 			data, ci, err := handle.ZeroCopyReadPacketData()
	// 			if err != nil {
	// 				fmtLogger.Error("Error reading packet data", slog.Any("error", err))
	// 			}
	// 			ts := ci.Timestamp
	// 			ln := ci.Length
	// 			if ln == 0 {
	// 				continue
	// 			}

	//			Handle(ts, data)
	//		}
	//		// packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//		// packetSource.NoCopy = true
	//		// packetSource.Lazy = true
	//		// packetSource.DecodeOptions.Lazy = true
	//		// packetSource.DecodeOptions.NoCopy = true
	//		// for packet := range packetSource.Packets() {
	//		// 	go Handle(packet)
	//		// }
	//	}
}

type DNSMatch struct {
	QTS   time.Time
	ATS   time.Time
	Src   string
	Dest  string
	Sport layers.UDPPort

	TID       uint16
	Query     string
	QueryType string

	IPAnswer    []net.IP
	CNAMEAnswer []string
	RCode       string
}

func (m DNSMatch) Log() {
	zipWritterLock.Lock()
	defer zipWritterLock.Unlock()

	ip_answer_list := []string{}
	for _, ip := range m.IPAnswer {
		ip_answer_list = append(ip_answer_list, ip.String())
	}

	tpl := "q_time=%v a_time=%v src=%v sport=%v dst=%v tid=%v q_name=%v q_type=%v a_ip=%v a_cname=%v error=%v\n"

	msg := fmt.Sprintf(tpl,
		m.QTS.Local().Format("2006-01-02T15:04:05.000000"),
		m.ATS.Local().Format("2006-01-02T15:04:05.000000"),
		m.Src,
		m.Sport,
		m.Dest,
		m.TID,
		m.Query,
		m.QueryType,
		strings.Join(ip_answer_list, ","),
		strings.Join(m.CNAMEAnswer, ","),
		m.RCode,
	)

	zipWritter.Write([]byte(msg))
}

func Handle(ts time.Time, packet_raw []byte) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var udp layers.UDP
	var dns layers.DNS
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &dns)
	decoded := []gopacket.LayerType{}

	if err := parser.DecodeLayers(packet_raw, &decoded); err != nil {
		fmtLogger.Debug("Could not parse packet", slog.Time("ts", ts), slog.Any("error", err))
		return
	}

	var sip net.IP = nil
	var dip net.IP = nil
	var sport layers.UDPPort
	var dport layers.UDPPort
	var isDNS = false

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv6:
			sip = ip6.SrcIP
			dip = ip6.DstIP
		case layers.LayerTypeIPv4:
			sip = ip4.SrcIP
			dip = ip4.DstIP
		case layers.LayerTypeUDP:
			sport = udp.SrcPort
			dport = udp.DstPort
		case layers.LayerTypeDNS:
			isDNS = true
			fmtLogger.Debug("DNS packet", "sip", sip, "dip", dip, "sport", sport, "dport", dport, "id", dns.ID)
		}
	}

	if !isDNS {
		fmtLogger.Debug("Not a DNS packet", slog.Time("ts", ts), slog.String("src", sip.String()), slog.String("dst", dip.String()))
		return
	}

	if !dns.QR {
		if len(dns.Questions) != 1 {
			fmtLogger.Warn("DNS packet with != 1 questions", slog.Time("ts", ts), slog.String("src", sip.String()), slog.String("dst", dip.String()), "tid", dns.ID)
			return
		}
		// Query
		match := DNSMatch{
			QTS:   ts,
			Src:   sip.String(),
			Dest:  dip.String(),
			Sport: sport,

			TID:       dns.ID,
			Query:     string(dns.Questions[0].Name),
			QueryType: dns.Questions[0].Type.String(),
		}

		key := fmt.Sprintf("%d-%v-%v", match.TID, sip.String(), dip.String())
		fmtLogger.Debug("DNS query", slog.Time("ts", ts), "key", key, "query", match)

		dnsMatchMap.Add(key, &match)
	} else {
		// Response
		tid := dns.ID
		key := fmt.Sprintf("%d-%v-%v", tid, dip.String(), sip.String())
		match, found := dnsMatchMap.Get(key)
		if !found {
			fmtLogger.Debug("No matching DNS query", slog.Time("ts", ts), slog.String("src", sip.String()), slog.String("dst", dip.String()), "tid", tid)

			if len(dns.Answers) < 1 {
				return
			}

			match = &DNSMatch{
				Src:       dip.String(),
				Dest:      sip.String(),
				Sport:     dport,
				TID:       dns.ID,
				Query:     string(dns.Answers[0].Name),
				QueryType: dns.Answers[0].Type.String(),
			}
			fmtLogger.Debug("create new DNS match", "key", key, "match", match)
		} else {
			fmtLogger.Debug("find matching DNS query", "key", key, "match", match)
			dnsMatchMap.Remove(key)
		}

		match.ATS = ts

		if dns.ResponseCode != layers.DNSResponseCodeNoErr {
			match.RCode = dns.ResponseCode.String()
		}

		for _, ans := range dns.Answers {
			switch ans.Type {
			case layers.DNSTypeA, layers.DNSTypeAAAA:
				match.IPAnswer = append(match.IPAnswer, ans.IP)
			case layers.DNSTypeCNAME:
				match.CNAMEAnswer = append(match.CNAMEAnswer, string(ans.CNAME))
			}
		}

		fmtLogger.Debug("DNS response", "response", match)

		if zipWritter != nil {
			match.Log()
		}
	}
}
