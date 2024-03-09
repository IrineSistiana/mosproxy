package dnsmsg

import (
	"sync"

	"github.com/IrineSistiana/mosproxy/internal/pool"
)

var (
	poolA    = sync.Pool{New: func() any { return new(A) }}
	poolAAAA = sync.Pool{New: func() any { return new(AAAA) }}
	poolMX   = sync.Pool{New: func() any { return new(MX) }}
	poolNAME = sync.Pool{New: func() any { return new(NAMEResource) }}
	poolSOA  = sync.Pool{New: func() any { return new(SOA) }}
	poolSRV  = sync.Pool{New: func() any { return new(SRV) }}
	poolRaw  = sync.Pool{New: func() any { return new(RawResource) }}
)

func NewA() *A               { return poolA.Get().(*A) }
func NewAAAA() *AAAA         { return poolAAAA.Get().(*AAAA) }
func NewMX() *MX             { return poolMX.Get().(*MX) }
func NewNAME() *NAMEResource { return poolNAME.Get().(*NAMEResource) }
func NewSOA() *SOA           { return poolSOA.Get().(*SOA) }
func NewSRV() *SRV           { return poolSRV.Get().(*SRV) }
func NewRaw() *RawResource   { return poolRaw.Get().(*RawResource) }

func ReleaseResource(r Resource) {
	switch r := r.(type) {
	case *A:
		ReleaseA(r)
	case *AAAA:
		ReleaseAAAA(r)
	case *MX:
		ReleaseMX(r)
	case *NAMEResource:
		ReleaseNAME(r)
	case *SOA:
		ReleaseSOA(r)
	case *SRV:
		ReleaseSRV(r)
	case *RawResource:
		ReleaseRaw(r)
	}
}

func releaseNameIfNotNil(n Name) {
	if n != nil {
		ReleaseName(n)
	}
}

func ReleaseA(r *A) {
	releaseNameIfNotNil(r.Name)
	*r = A{}
	poolA.Put(r)
}

func ReleaseAAAA(r *AAAA) {
	releaseNameIfNotNil(r.Name)
	*r = AAAA{}
	poolAAAA.Put(r)
}

func ReleaseMX(r *MX) {
	releaseNameIfNotNil(r.Name)
	releaseNameIfNotNil(r.MX)
	*r = MX{}
	poolMX.Put(r)
}

func ReleaseNAME(r *NAMEResource) {
	releaseNameIfNotNil(r.Name)
	releaseNameIfNotNil(r.NameData)
	*r = NAMEResource{}
	poolNAME.Put(r)
}

func ReleaseSOA(r *SOA) {
	releaseNameIfNotNil(r.Name)
	releaseNameIfNotNil(r.NS)
	releaseNameIfNotNil(r.MBox)
	*r = SOA{}
	poolSOA.Put(r)
}

func ReleaseSRV(r *SRV) {
	releaseNameIfNotNil(r.Name)
	releaseNameIfNotNil(r.Target)
	*r = SRV{}
	poolSRV.Put(r)
}

func ReleaseRaw(r *RawResource) {
	releaseNameIfNotNil(r.Name)
	if r.Data != nil {
		pool.ReleaseBuf(r.Data)
	}
	*r = RawResource{}
	poolRaw.Put(r)
}
