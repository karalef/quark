package callibrate

import (
	"errors"
	"math"
	"time"

	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/spf13/cobra"
)

var callibrateFlags struct {
	cost    kdf.Argon2Cost
	desired timing
	rounds  uint
	strict  bool
}

func init() {
	flags := Callibrate.LocalFlags()
	flags.Uint32VarP(&callibrateFlags.cost.Memory, "maxmem", "m", 0, "maximum memory to use (KiB)")
	Callibrate.MarkFlagRequired("maxmem")
	flags.Uint8VarP(&callibrateFlags.cost.Threads, "threads", "p", 4, "number of threads to use")
	flags.DurationVarP(&callibrateFlags.desired.avg, "desired", "e", time.Second, "desired duration")
	flags.DurationVarP(&callibrateFlags.desired.dev, "accuracy", "d", time.Second, "accuracy threshold")
	flags.UintVarP(&callibrateFlags.rounds, "rounds", "r", 10, "number of test rounds")
	flags.BoolVarP(&callibrateFlags.strict, "strict", "s", false, "turning the accuracy flag to the deviation threshold")
}

var Callibrate = &cobra.Command{
	Use:       "callibrate",
	Aliases:   []string{"cal"},
	Short:     "callibrate the KDF",
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgs: []string{"argon2i", "argon2id"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if callibrateFlags.cost.Memory == 0 ||
			callibrateFlags.desired.dev == 0 ||
			callibrateFlags.desired.avg == 0 ||
			callibrateFlags.cost.Threads == 0 ||
			callibrateFlags.rounds == 0 {
			return errors.New("invalid parameters")
		}
		callibrateFlags.cost.Time = 1
		start := time.Now()
		avg, err := calArgon2i(&callibrateFlags.cost, callibrateFlags.rounds)
		if err != nil {
			cmdio.Println("callibration error:", err.Error())
			return nil
		}
		elapsed := time.Since(start)

		cmdio.Println("time:", callibrateFlags.cost.Time)
		cmdio.Printf("memory: %d KiB\n", callibrateFlags.cost.Memory)
		cmdio.Println("threads:", callibrateFlags.cost.Threads)
		cmdio.Printf("average: %s; deviation: %s\n", avg.avg, avg.dev)
		cmdio.Println("callibration took", elapsed.Seconds(), "seconds")

		return nil
	},
}

var (
	errCallibration  = errors.New("callibration error")
	errHighDeviation = errors.New("very high deviation")
)

type timing struct {
	avg time.Duration
	dev time.Duration
}

func (t timing) min() time.Duration { return t.avg - t.dev }
func (t timing) max() time.Duration { return t.avg + t.dev }

func (t timing) hasPoint(p time.Duration) bool {
	return t.min() <= p && p <= t.max()
}

func (t timing) has(other timing) bool {
	return t.min() <= other.min() && t.max() >= other.max()
}

func (t timing) compare(other timing, strict bool) int {
	if strict {
		if other.has(t) {
			return 0
		}
		if t.min() < other.min() && t.max() > other.max() &&
			other.hasPoint(t.avg) {
			return 2
		}
		if t.min() < other.min() {
			return -1
		}
		return 1
	}
	if other.min() > t.avg {
		return -1
	}
	if other.max() < t.avg {
		return 1
	}
	return 0
}

func probeKDF(s kdf.Scheme, cost kdf.Cost, times uint) (timing, error) {
	k, err := s.New(cost)
	if err != nil {
		return timing{}, err
	}
	salt := []byte("saltsaltsalt")
	password := []byte("password")
	var total time.Duration
	res := make([]time.Duration, times)
	var average timing
	for i := range times {
		start := time.Now()
		_ = k.Derive(password, salt, 32)
		res[i] = time.Since(start)
		total += res[i]
	}
	average.avg = total / time.Duration(times)
	var variance float64
	for i := range res {
		variance += math.Pow(float64((res[i] - average.avg).Microseconds()), 2)
	}
	average.dev = time.Duration(math.Sqrt(variance/float64(times)) * 1e3)
	return average, nil
}
