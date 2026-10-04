package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

var agentChunkSizes sync.Map

func getAgentChunkSize(agentId int64) int {
	if v, ok := agentChunkSizes.Load(agentId); ok {
		return v.(int)
	}
	return UPLOAD_CHUNK_DEFAULT
}

func humanSize(n int) string {
	if n >= 1024*1024 && n%(1024*1024) == 0 {
		return fmt.Sprintf("%dMB", n/(1024*1024))
	}
	if n >= 1024 && n%1024 == 0 {
		return fmt.Sprintf("%dKB", n/1024)
	}
	return fmt.Sprintf("%d bytes", n)
}

func parseChunkSize(raw string) (int, error) {
	raw = strings.TrimSpace(strings.ToUpper(raw))
	multiplier := 1
	if strings.HasSuffix(raw, "MB") {
		multiplier = 1024 * 1024
		raw = strings.TrimSuffix(raw, "MB")
	} else if strings.HasSuffix(raw, "KB") {
		multiplier = 1024
		raw = strings.TrimSuffix(raw, "KB")
	} else if strings.HasSuffix(raw, "B") {
		raw = strings.TrimSuffix(raw, "B")
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid chunk size: %w", err)
	}
	size := n * multiplier
	if size < UPLOAD_CHUNK_MIN {
		return 0, fmt.Errorf("chunk size too small (min %d bytes)", UPLOAD_CHUNK_MIN)
	}
	if size > UPLOAD_CHUNK_MAX {
		return 0, fmt.Errorf("chunk size too large (max %d bytes / %dMB)", UPLOAD_CHUNK_MAX, UPLOAD_CHUNK_MAX/(1024*1024))
	}
	return size, nil
}
