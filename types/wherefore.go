package types

import "time"

type Pan interface {
	String() string
	AddTransfer(uint64)
	Transfered() uint64
	ResetTransfered()
	LastUpdate()
	Age() time.Duration
	Flush()
}
