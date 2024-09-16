package dnsmsg

import (
	"sync"
)

var (
	poolA     = sync.Pool{New: func() any { return new(A) }}
	poolAAAA  = sync.Pool{New: func() any { return new(AAAA) }}
	poolMX    = sync.Pool{New: func() any { return new(MX) }}
	poolNAME  = sync.Pool{New: func() any { return new(NAMEResource) }}
	poolSOA   = sync.Pool{New: func() any { return new(SOA) }}
	poolSRV   = sync.Pool{New: func() any { return new(SRV) }}
	poolRaw   = sync.Pool{New: func() any { return new(RawResource) }}
	poolRrHdr = sync.Pool{New: func() any { return new(ResourceHdr) }}
)

func NewA() *A               { return poolA.Get().(*A) }
func NewAAAA() *AAAA         { return poolAAAA.Get().(*AAAA) }
func NewMX() *MX             { return poolMX.Get().(*MX) }
func NewNAME() *NAMEResource { return poolNAME.Get().(*NAMEResource) }
func NewSOA() *SOA           { return poolSOA.Get().(*SOA) }
func NewSRV() *SRV           { return poolSRV.Get().(*SRV) }
func NewRaw() *RawResource   { return poolRaw.Get().(*RawResource) }
func newRrHdr() *ResourceHdr { return poolRrHdr.Get().(*ResourceHdr) }

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

func ReleaseA(r *A) {
	r.reset()
	poolA.Put(r)
}

func ReleaseAAAA(r *AAAA) {
	r.reset()
	poolAAAA.Put(r)
}

func ReleaseMX(r *MX) {
	r.reset()
	poolMX.Put(r)
}

func ReleaseNAME(r *NAMEResource) {
	r.reset()
	poolNAME.Put(r)
}

func ReleaseSOA(r *SOA) {
	r.reset()
	poolSOA.Put(r)
}

func ReleaseSRV(r *SRV) {
	r.reset()
	poolSRV.Put(r)
}

func ReleaseRaw(r *RawResource) {
	r.reset()
	poolRaw.Put(r)
}

func releaseRrHdr(hdr *ResourceHdr) {
	hdr.reset()
	poolRrHdr.Put(hdr)
}
