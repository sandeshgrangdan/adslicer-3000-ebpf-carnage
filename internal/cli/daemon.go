package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/hash"
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/lists"
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/loader"
	"github.com/spf13/cobra"
)

func newDaemonCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "load programs, attach to interfaces, refresh lists, stream events",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			return runDaemon(cmd.Context(), cfg)
		},
	}
	cmd.Flags().StringVar(&configPath, "config",
		"/etc/adblocker/adblocker.yaml", "path to YAML config")
	return cmd
}

func runDaemon(ctx context.Context, cfg *Config) error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	l, err := loader.New(cfg.Interfaces)
	if err != nil {
		return err
	}
	defer l.Close()

	log.Printf("attached. pin dir=%s", loader.PinDir)

	// SIGHUP triggers an immediate list refresh.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		listRefresher(ctx, l, cfg, hup)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		expiryReaper(ctx, l, time.Duration(cfg.CleanupIntervalSeconds)*time.Second)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		eventReader(ctx, l)
	}()

	select {
	case sig := <-stop:
		log.Printf("got %v, shutting down", sig)
	case <-ctx.Done():
	}
	cancel()
	wg.Wait()
	return nil
}

func listRefresher(ctx context.Context, l *loader.Loader, cfg *Config, hup <-chan os.Signal) {
	refresh := func() {
		log.Printf("list refresh starting (%d sources)", len(cfg.Sources))
		domains, errs := lists.FetchAll(ctx, cfg.Sources)
		for _, e := range errs {
			log.Printf("source error: %v", e)
		}
		domains = append(domains, cfg.StaticBlock...)
		if err := bulkLoad(l.Blocklist(), domains, loader.FlagBlock); err != nil {
			log.Printf("bulk load blocklist: %v", err)
		} else {
			log.Printf("loaded %d blocklist entries", len(domains))
		}
		// Allowlist file overrides upstream lists.
		if al, err := readAllowlist(cfg.AllowlistFile); err != nil {
			log.Printf("allowlist read: %v", err)
		} else if len(al) > 0 {
			if err := bulkLoad(l.Blocklist(), al, loader.FlagAllow); err != nil {
				log.Printf("bulk load allowlist: %v", err)
			} else {
				log.Printf("loaded %d allowlist overrides", len(al))
			}
		}
	}

	refresh()
	t := time.NewTicker(time.Duration(cfg.UpdateIntervalHours) * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		case <-hup:
			log.Printf("SIGHUP -> manual refresh")
			refresh()
		}
	}
}

func bulkLoad(m *ebpf.Map, domains []string, flags uint8) error {
	const batch = 4096
	keys := make([]uint64, 0, batch)
	vals := make([]loader.DomainEntry, 0, batch)
	flush := func() error {
		if len(keys) == 0 {
			return nil
		}
		if _, err := m.BatchUpdate(keys, vals, &ebpf.BatchOptions{}); err != nil {
			return err
		}
		keys = keys[:0]
		vals = vals[:0]
		return nil
	}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !lists.ValidDomain(d) {
			continue
		}
		keys = append(keys, hash.SumString(d))
		vals = append(vals, loader.DomainEntry{Flags: flags})
		if len(keys) >= batch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

func readAllowlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return lists.ParseDomain(f)
}

// expiryReaper iterates the blocklist every `interval`, deleting entries
// whose TEMP flag is set, ExpiresAt != 0, and ExpiresAt < now.
func expiryReaper(ctx context.Context, l *loader.Loader, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := uint64(time.Now().UnixNano())
			var (
				key      uint64
				entry    loader.DomainEntry
				toDelete []uint64
			)
			it := l.Blocklist().Iterate()
			for it.Next(&key, &entry) {
				if entry.Flags&loader.FlagTemp != 0 &&
					entry.ExpiresAt != 0 &&
					entry.ExpiresAt < now {
					toDelete = append(toDelete, key)
				}
			}
			if err := it.Err(); err != nil {
				log.Printf("reaper iterate: %v", err)
				continue
			}
			for _, k := range toDelete {
				if err := l.Blocklist().Delete(&k); err != nil {
					log.Printf("reaper delete %016x: %v", k, err)
				}
			}
			if len(toDelete) > 0 {
				log.Printf("reaper: deleted %d expired entries", len(toDelete))
			}
		}
	}
}

func eventReader(ctx context.Context, l *loader.Loader) {
	r, err := l.Events()
	if err != nil {
		log.Printf("ringbuf reader: %v", err)
		return
	}
	defer r.Close()

	go func() {
		<-ctx.Done()
		_ = r.Close()
	}()

	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			return
		}
		if len(rec.RawSample) < 24 {
			continue
		}
		ev := decodeEvent(rec.RawSample)
		log.Printf("BLOCK[%s] %s -> %s (%s)",
			reasonName(ev.Reason),
			ipFromU32(ev.Saddr),
			ipFromU32(ev.Daddr),
			cstring(ev.Qname[:]),
		)
	}
}

func decodeEvent(b []byte) loader.BlockEvent {
	var e loader.BlockEvent
	if len(b) < int(reflectSizeOf(e)) {
		return e
	}
	e.TsNs = binary.LittleEndian.Uint64(b[0:8])
	e.DomainHash = binary.LittleEndian.Uint64(b[8:16])
	e.Saddr = binary.LittleEndian.Uint32(b[16:20])
	e.Daddr = binary.LittleEndian.Uint32(b[20:24])
	e.Sport = binary.LittleEndian.Uint16(b[24:26])
	e.Dport = binary.LittleEndian.Uint16(b[26:28])
	e.Reason = b[28]
	// 7 bytes pad b[29..36]
	copy(e.Qname[:], b[36:36+128])
	return e
}

// reflectSizeOf returns the expected wire size of a BlockEvent (in
// case Go padding shifts; written out explicitly to keep loader free
// of `reflect`).
func reflectSizeOf(_ loader.BlockEvent) uintptr {
	// 8 + 8 + 4 + 4 + 2 + 2 + 1 + 7 + 128 = 164
	return 164
}

func reasonName(r uint8) string {
	switch r {
	case loader.ReasonDNS:
		return "DNS"
	case loader.ReasonSNI:
		return "SNI"
	case loader.ReasonIP:
		return "IP"
	default:
		return fmt.Sprintf("?%d", r)
	}
}

func ipFromU32(v uint32) string {
	// kernel writes host-order in events; format as dotted quad
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
