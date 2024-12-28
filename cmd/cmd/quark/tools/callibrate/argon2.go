package callibrate

import (
	"time"

	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/crypto/kdf"
)

func calArgon2i(cost *kdf.Argon2Cost, rounds uint) (timing, error) {
	maxMem := cost.Memory
	desired := callibrateFlags.desired
	strict := callibrateFlags.strict

	cmdio.Println(":: calibrating Argon2i...")
	cmdio.Println(":: probing max memory")
	// first probe with maximum memory
	avg, err := probeKDF(kdf.Argon2i, cost, rounds)
	if err != nil {
		return avg, err
	}
	cmdio.Printf(":: average: %s\n", avg.avg)
	cmp := avg.compare(desired, strict)
	switch cmp {
	case 0:
		return avg, nil
	case 2:
		return avg, errHighDeviation
	case 1: // too slow, decrease memory
	case -1: // too fast, increase rounds
		cmdio.Println(":: starting increasing rounds")
		goal := desired.avg
		if strict {
			goal = desired.max()
		}
		for cmp == -1 {
			times := float64(goal) / float64(avg.avg) * float64(cost.Time)
			cost.Time = uint32(times)
			if float64(cost.Time) < times {
				cost.Time++
			}
			cmdio.Println(":: rounds increased to", cost.Time)
			avg, err = probeKDF(kdf.Argon2i, cost, rounds)
			if err != nil {
				return avg, err
			}
			cmp = avg.compare(desired, strict)
		}
		if cmp == 0 {
			return avg, nil
		}
		if cmp == 2 {
			return avg, errHighDeviation
		}
		roundTime := avg.avg / time.Duration(cost.Time)
		extra := uint32((avg.avg - desired.avg) / roundTime)
		if extra == 0 || extra-1 == 0 {
			break
		}
		extra--
		cmdio.Println(":: starting decreasing rounds")
		cost.Time -= extra
		cmdio.Println(":: rounds decresed to", cost.Time)
		avg, err = probeKDF(kdf.Argon2i, cost, rounds)
		if err != nil {
			return avg, err
		}
		switch cmp = avg.compare(desired, strict); cmp {
		case -1:
			cost.Time++
		case 0:
			return avg, nil
		case 1:
		case 2:
			return avg, errHighDeviation
		}
	}

	cmdio.Println(":: starting decreasing memory")
	minmem, maxmem := uint32(0), maxMem
	cmdio.Println(":: memory decreased to", (minmem+maxmem)/2)
	for cmp != 0 && minmem < maxmem && maxmem-minmem > 1 {
		cost.Memory = (minmem + maxmem) / 2
		avg, err = probeKDF(kdf.Argon2i, cost, rounds)
		if err != nil {
			return avg, err
		}
		cmp = avg.compare(desired, strict)
		switch cmp {
		case 0:
			return avg, nil
		case 2:
			return avg, errHighDeviation
		case 1: // too slow, decrease memory
			maxmem = cost.Memory
			cmdio.Println(":: memory decreased to", (minmem+maxmem)/2)
		case -1: // too fast, increase memory
			minmem = cost.Memory
			cmdio.Println(":: memory increased to", (minmem+maxmem)/2)
		}
	}

	return avg, errHighDeviation
}
