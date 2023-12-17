package pool

import "bufio"

var BufWriterPool1K = NewSyncPool[bufio.Writer](SyncPoolOpts[bufio.Writer]{
	New:       func() *bufio.Writer { return bufio.NewWriterSize(nil, 1024) },
	OnRelease: func(v *bufio.Writer) { v.Reset(nil) },
})

var BufReaderPool1K = NewSyncPool[bufio.Reader](SyncPoolOpts[bufio.Reader]{
	New:       func() *bufio.Reader { return bufio.NewReaderSize(nil, 1024) },
	OnRelease: func(v *bufio.Reader) { v.Reset(nil) },
})
