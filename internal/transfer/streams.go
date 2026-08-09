package transfer

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"example.com/pro-transfer/internal/protocol"
)

const maxParallelStreams = 8

type planRange struct {
	Start      int
	End        int // exclusive
	CipherSize int64
	PlainSize  int64
}

func splitPlanRanges(plans []chunkPlan, streams int) []planRange {
	if streams < 1 {
		streams = 1
	}
	if streams > maxParallelStreams {
		streams = maxParallelStreams
	}
	if len(plans) == 0 {
		return []planRange{{Start: 0, End: 0}}
	}
	if streams > len(plans) {
		streams = len(plans)
	}
	total := int64(0)
	for _, p := range plans {
		total += p.CipherSize
	}
	ranges := make([]planRange, 0, streams)
	start := 0
	consumed := int64(0)
	for stream := 0; stream < streams; stream++ {
		remainingStreams := streams - stream
		if remainingStreams == 1 {
			r := makeRange(plans, start, len(plans))
			ranges = append(ranges, r)
			break
		}
		remainingBytes := total - consumed
		target := remainingBytes / int64(remainingStreams)
		end := start
		var size int64
		// Keep at least one plan for every remaining stream.
		maxEnd := len(plans) - (remainingStreams - 1)
		for end < maxEnd {
			next := plans[end].CipherSize
			if end > start && size+next > target {
				break
			}
			size += next
			end++
		}
		if end == start {
			end++
		}
		r := makeRange(plans, start, end)
		ranges = append(ranges, r)
		consumed += r.CipherSize
		start = end
	}
	return ranges
}

func makeRange(plans []chunkPlan, start, end int) planRange {
	r := planRange{Start: start, End: end}
	for i := start; i < end; i++ {
		r.CipherSize += plans[i].CipherSize
		r.PlainSize += int64(plans[i].PlainSize)
	}
	return r
}

func streamPayloadSizes(ranges []planRange) []int64 {
	out := make([]int64, len(ranges))
	for i, r := range ranges {
		out[i] = r.CipherSize
	}
	return out
}

func streamPlanIndexForOffset(plans []chunkPlan, r planRange, offset int64) (int, error) {
	if offset < 0 || offset > r.CipherSize {
		return 0, errors.New("stream resume offset out of range")
	}
	if offset == 0 {
		return r.Start, nil
	}
	cur := int64(0)
	for i := r.Start; i < r.End; i++ {
		cur += plans[i].CipherSize
		if cur == offset {
			return i + 1, nil
		}
		if cur > offset {
			return 0, errors.New("stream resume offset is not a chunk boundary")
		}
	}
	if offset == r.CipherSize {
		return r.End, nil
	}
	return 0, errors.New("stream resume offset invalid")
}

func streamPlainDone(plans []chunkPlan, r planRange, offset int64) (int64, error) {
	idx, err := streamPlanIndexForOffset(plans, r, offset)
	if err != nil {
		return 0, err
	}
	var done int64
	for i := r.Start; i < idx; i++ {
		done += int64(plans[i].PlainSize)
	}
	return done, nil
}

func sendEncryptedRange(conn net.Conn, aead cipher.AEAD, plans []chunkPlan, start, end int, progress *ProgressWriter) error {
	return sendEncryptedChunksRange(conn, aead, plans, start, end, progress)
}

func receiveEncryptedRange(conn net.Conn, aead cipher.AEAD, staging *receiverStaging, plans []chunkPlan, streamID, start, end int, progress *ProgressWriter) error {
	return receiveEncryptedChunksRange(conn, aead, staging, plans, streamID, start, end, progress)
}

type connGroup struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (g *connGroup) add(c net.Conn) {
	g.mu.Lock()
	g.conns = append(g.conns, c)
	g.mu.Unlock()
}
func (g *connGroup) closeAll() {
	g.mu.Lock()
	conns := append([]net.Conn(nil), g.conns...)
	g.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func sendPublicStreams(cfg ClientConfig, room, attachToken string, aead cipher.AEAD, plans []chunkPlan, ranges []planRange, offsets []int64, progress *ProgressWriter) error {
	if len(ranges) != len(offsets) {
		return errors.New("stream offset count mismatch")
	}
	errs := make(chan error, len(ranges))
	var wg sync.WaitGroup
	group := &connGroup{}
	for streamID, r := range ranges {
		idx, err := streamPlanIndexForOffset(plans, r, offsets[streamID])
		if err != nil {
			return err
		}
		if idx >= r.End {
			continue
		}
		wg.Add(1)
		go func(streamID int, r planRange, start int) {
			defer wg.Done()
			conn, err := cfg.dial()
			if err != nil {
				errs <- err
				group.closeAll()
				return
			}
			group.add(conn)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(effectiveIOTimeout(cfg)))
			if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeDataSend, Room: room, Stream: streamID, Token: attachToken}); err != nil {
				errs <- err
				group.closeAll()
				return
			}
			ack, err := protocol.ReadMessage(conn)
			if err != nil {
				errs <- err
				group.closeAll()
				return
			}
			if ack.Type == protocol.TypeError {
				errs <- errors.New(ack.Text)
				group.closeAll()
				return
			}
			if ack.Type != protocol.TypeJoined {
				errs <- fmt.Errorf("data stream %d ack noto'g'ri", streamID)
				group.closeAll()
				return
			}
			if err := sendEncryptedRange(conn, aead, plans, start, r.End, progress); err != nil {
				errs <- err
				group.closeAll()
				return
			}
		}(streamID, r, idx)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		select {
		case err := <-errs:
			return err
		default:
			return nil
		}
	case err := <-errs:
		group.closeAll()
		<-done
		return err
	}
}

func receivePublicStreams(cfg ClientConfig, room, attachToken string, aead cipher.AEAD, staging *receiverStaging, plans []chunkPlan, ranges []planRange, offsets []int64, progress *ProgressWriter) error {
	if len(ranges) != len(offsets) {
		return errors.New("stream offset count mismatch")
	}
	errs := make(chan error, len(ranges))
	var wg sync.WaitGroup
	group := &connGroup{}
	for streamID, r := range ranges {
		idx, err := streamPlanIndexForOffset(plans, r, offsets[streamID])
		if err != nil {
			return err
		}
		if idx >= r.End {
			continue
		}
		wg.Add(1)
		go func(streamID int, r planRange, start int) {
			defer wg.Done()
			conn, err := cfg.dial()
			if err != nil {
				errs <- err
				group.closeAll()
				return
			}
			group.add(conn)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(effectiveIOTimeout(cfg)))
			if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeDataReceive, Room: room, Stream: streamID, Token: attachToken}); err != nil {
				errs <- err
				group.closeAll()
				return
			}
			ack, err := protocol.ReadMessage(conn)
			if err != nil {
				errs <- err
				group.closeAll()
				return
			}
			if ack.Type == protocol.TypeError {
				errs <- errors.New(ack.Text)
				group.closeAll()
				return
			}
			if ack.Type != protocol.TypeJoined {
				errs <- fmt.Errorf("data stream %d ack noto'g'ri", streamID)
				group.closeAll()
				return
			}
			if err := receiveEncryptedRange(conn, aead, staging, plans, streamID, start, r.End, progress); err != nil {
				errs <- err
				group.closeAll()
				return
			}
		}(streamID, r, idx)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		select {
		case err := <-errs:
			return err
		default:
			return nil
		}
	case err := <-errs:
		group.closeAll()
		<-done
		return err
	}
}
