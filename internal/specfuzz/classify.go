package specfuzz

// Class is the outcome of comparing one target-adapter verdict to the
// oracle for one input.
type Class string

const (
	// Conformant: adapter and oracle agree.
	Conformant Class = "conformant"
	// Deviates: oracle rejects, adapter accepts.
	Deviates Class = "deviates"
	// OverStrict: oracle accepts, adapter rejects.
	OverStrict Class = "over-strict"
)

// PeerClass is the outcome of comparing the target's verdict to one
// reference adapter's verdict on the same input.
type PeerClass string

const (
	// PeerAgree: same accept/reject and (if both accept) same body.
	PeerAgree PeerClass = "agree"
	// PeerAcceptError: one accepts, the other rejects/errors.
	PeerAcceptError PeerClass = "accept-vs-error"
	// PeerBoundary: both accept, consumed byte counts differ.
	PeerBoundary PeerClass = "boundary-diff"
	// PeerValue: both accept, body_hex differs (consumed unavailable).
	PeerValue PeerClass = "value-diff"
)

// Differential is the target-vs-one-reference comparison for one input.
type Differential struct {
	Peer    string    `json:"peer"`
	Version string    `json:"version,omitempty"`
	Class   PeerClass `json:"class"`
}

// Result is one classified corpus input.
type Result struct {
	Input         CorpusInput    `json:"input"`
	Oracle        OracleVerdict  `json:"oracle"`
	Target        AdapterVerdict `json:"target"`
	Class         Class          `json:"class"`
	Differentials []Differential `json:"differentials"`
}

// Classify computes the class and per-reference differentials for one
// input. matrixRow may be nil (e.g. for controls not in the matrix).
func Classify(oracle OracleVerdict, target AdapterVerdict, matrixRow *MatrixRow, versions map[string]string) (Class, []Differential) {
	var cls Class
	switch {
	case oracle.Valid == target.Accept:
		cls = Conformant
	case target.Accept:
		cls = Deviates
	default:
		cls = OverStrict
	}
	if matrixRow == nil {
		return cls, nil
	}
	diffs := make([]Differential, 0, len(matrixRow.Adapters))
	for peer, pv := range matrixRow.Adapters {
		diffs = append(diffs, Differential{
			Peer:    peer,
			Version: versions[peer],
			Class:   classifyPeer(target, pv),
		})
	}
	return cls, diffs
}

func classifyPeer(target, peer AdapterVerdict) PeerClass {
	if target.Accept != peer.Accept {
		return PeerAcceptError
	}
	if !target.Accept {
		return PeerAgree
	}
	if target.Consumed != nil && peer.Consumed != nil && *target.Consumed != *peer.Consumed {
		return PeerBoundary
	}
	if target.BodyHex != peer.BodyHex {
		return PeerValue
	}
	return PeerAgree
}

// AnyBoundary reports whether any differential is boundary- or
// value-class, i.e. the target and at least one reference both accept
// but disagree on where the message ended or what it contained.
func AnyBoundary(diffs []Differential) bool {
	for _, d := range diffs {
		if d.Class == PeerBoundary || d.Class == PeerValue {
			return true
		}
	}
	return false
}
