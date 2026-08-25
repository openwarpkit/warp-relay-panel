package adaptivelimit

import (
	"math"
	"time"
)

const DecimalTB = 1_000_000_000_000

var zone = time.FixedZone("MSK", 3*60*60)

type Config struct {
	DefaultLimitMbps float64
	MinLimitMbps     float64
	MonthlyBudgetTB  float64
	Direction        string
}

type Usage struct {
	Month   string
	TXBytes int64
	RXBytes int64
}

type Status struct {
	Enabled             bool    `json:"enabled"`
	Direction           string  `json:"direction"`
	BudgetTB            float64 `json:"budget_tb"`
	UsedTB              float64 `json:"used_tb"`
	RemainingTB         float64 `json:"remaining_tb"`
	ExpectedTB          float64 `json:"expected_tb"`
	ForecastTB          float64 `json:"forecast_tb"`
	Pace                float64 `json:"pace"`
	RecentMbps          float64 `json:"recent_mbps"`
	TargetMbps          float64 `json:"target_mbps"`
	DefaultLimitMbps    float64 `json:"default_limit_mbps"`
	MinLimitMbps        float64 `json:"min_limit_mbps"`
	CurrentLimitMbps    float64 `json:"current_limit_mbps"`
	DesiredLimitMbps    float64 `json:"desired_limit_mbps"`
	UnachievableAtFloor bool    `json:"unachievable_at_floor"`
	UpdatedAt           string  `json:"updated_at,omitempty"`
	Error               string  `json:"error,omitempty"`
}

type Sample struct {
	Month string
	Bytes int64
	At    time.Time
}

type Decision struct {
	Limit  float64
	Status Status
}

func UsageBytes(usage Usage, direction string) int64 {
	switch direction {
	case "rx":
		return usage.RXBytes
	case "total":
		return usage.TXBytes + usage.RXBytes
	default:
		return usage.TXBytes
	}
}

func NewSample(usage Usage, direction string, now time.Time) *Sample {
	now = now.In(zone)
	return &Sample{Month: now.Format("2006-01"), Bytes: UsageBytes(usage, direction), At: now}
}

func Calculate(cfg Config, current float64, usage Usage, previous *Sample, now time.Time) Decision {
	now = now.In(zone)
	if cfg.MonthlyBudgetTB <= 0 {
		return Decision{Limit: current, Status: Status{
			Enabled:          false,
			Direction:        cfg.Direction,
			DefaultLimitMbps: cfg.DefaultLimitMbps,
			MinLimitMbps:     cfg.MinLimitMbps,
			CurrentLimitMbps: current,
			DesiredLimitMbps: current,
			UpdatedAt:        now.Format(time.RFC3339),
		}}
	}
	month := now.Format("2006-01")
	used := UsageBytes(usage, cfg.Direction)
	if usage.Month != "" && usage.Month != month {
		used = 0
	}
	if used < 0 {
		used = 0
	}

	budgetBytes := cfg.MonthlyBudgetTB * DecimalTB
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, zone)
	monthEnd := monthStart.AddDate(0, 1, 0)
	elapsed := now.Sub(monthStart).Seconds()
	monthSeconds := monthEnd.Sub(monthStart).Seconds()
	remainingSeconds := monthEnd.Sub(now).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}
	if remainingSeconds < 1 {
		remainingSeconds = 1
	}

	expectedBytes := budgetBytes * elapsed / monthSeconds
	remainingBytes := budgetBytes - float64(used)
	if remainingBytes < 0 {
		remainingBytes = 0
	}
	targetBytesPerSecond := remainingBytes / remainingSeconds
	pace := 0.0
	if expectedBytes > 0 {
		pace = float64(used) / expectedBytes
	}
	forecastBytes := float64(used) / elapsed * monthSeconds

	recentBytesPerSecond := 0.0
	hasRecent := false
	if previous != nil && previous.Month == month && used >= previous.Bytes {
		dt := now.Sub(previous.At).Seconds()
		if dt >= 30 {
			recentBytesPerSecond = float64(used-previous.Bytes) / dt
			hasRecent = true
		}
	}

	desired := cfg.DefaultLimitMbps
	if float64(used) >= budgetBytes {
		desired = cfg.MinLimitMbps
	} else if hasRecent && recentBytesPerSecond > 0 {
		desired = current * targetBytesPerSecond / recentBytesPerSecond
	} else if pace > 1 {
		desired = cfg.DefaultLimitMbps / pace
	}
	desired = quantize(desired, cfg.MinLimitMbps, cfg.DefaultLimitMbps)
	if desired > current+0.5 {
		desired = current + 0.5
	}
	if float64(used) < budgetBytes && desired < current-1.0 {
		desired = current - 1.0
	}
	desired = quantize(desired, cfg.MinLimitMbps, cfg.DefaultLimitMbps)

	status := Status{
		Enabled:             cfg.MonthlyBudgetTB > 0,
		Direction:           cfg.Direction,
		BudgetTB:            cfg.MonthlyBudgetTB,
		UsedTB:              float64(used) / DecimalTB,
		RemainingTB:         remainingBytes / DecimalTB,
		ExpectedTB:          expectedBytes / DecimalTB,
		ForecastTB:          forecastBytes / DecimalTB,
		Pace:                pace,
		RecentMbps:          recentBytesPerSecond * 8 / 1_000_000,
		TargetMbps:          targetBytesPerSecond * 8 / 1_000_000,
		DefaultLimitMbps:    cfg.DefaultLimitMbps,
		MinLimitMbps:        cfg.MinLimitMbps,
		CurrentLimitMbps:    current,
		DesiredLimitMbps:    desired,
		UnachievableAtFloor: current <= cfg.MinLimitMbps && hasRecent && recentBytesPerSecond > targetBytesPerSecond*1.05,
		UpdatedAt:           now.Format(time.RFC3339),
	}
	return Decision{Limit: desired, Status: status}
}

func quantize(value, minValue, maxValue float64) float64 {
	if value < minValue {
		value = minValue
	}
	if value > maxValue {
		value = maxValue
	}
	value = math.Floor(value*2) / 2
	if value < minValue {
		return minValue
	}
	return value
}
