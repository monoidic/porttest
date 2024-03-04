package main

import (
	"fmt"
	"iter"
	"log"
	"strconv"
	"strings"

	"github.com/monoidic/porttest/common"
)

// converts numbers, e.g 1,2,3,4,5,6,7,8,10,11,12,14,16,17,18 to ranges, e.g 1-8,10-12,14,16-18
// expects the numbers in order
func numsToRanges(ports iter.Seq[uint16]) iter.Seq[string] {
	return func(yield func(V string) bool) {
		next, stop := iter.Pull(ports)
		defer stop()
		rangeStart, ok := next()
		if !ok {
			return
		}

		prevNum := rangeStart
		for num, ok := next(); ok; num, ok = next() {
			if num != prevNum+1 {
				// yield previous range, start new one
				if !yield(formatRange(rangeStart, prevNum)) {
					return
				}
				rangeStart = num
			}
			prevNum = num
		}
		// final range
		yield(formatRange(rangeStart, prevNum))
	}
}

func formatRange(start, end uint16) string {
	if start == end {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// parse port string, e.g 80,443,600-700, and returns an iterator
// with the resulting port numbers
func parsePortString(portS string) iter.Seq[uint16] {
	return func(yield func(V uint16) bool) {
		for _, s := range strings.Split(portS, ",") {
			if !strings.Contains(s, "-") {
				if !yield(uint16(common.Check1(strconv.ParseUint(s, 10, 16)))) {
					return
				}
				continue
			}
			startEnd := strings.SplitN(s, "-", 2)
			start := common.Check1(strconv.ParseUint(startEnd[0], 10, 16))
			end := common.Check1(strconv.ParseUint(startEnd[1], 10, 16))
			if start >= end {
				log.Panicf("invalid port range, %d >= %d (start >= end)", start, end)
			}

			for i := start; i <= end; i++ {
				if !yield(uint16(i)) {
					return
				}
			}
		}
	}
}
