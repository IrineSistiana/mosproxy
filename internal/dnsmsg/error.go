package dnsmsg

import "errors"

var (
	ErrSmallBuffer = errors.New("buffer is too small")

	// copied from dnsmessage
	// TODO: remove unused errors.
	errBaseLen            = errors.New("insufficient data for base length type")
	errCalcLen            = errors.New("insufficient data for calculated length type")
	errReserved           = errors.New("segment prefix is reserved")
	errTooManyPtr         = errors.New("too many pointers (>10)")
	errInvalidPtr         = errors.New("invalid pointer")
	errInvalidName        = errors.New("invalid dns name")
	errNilResouceBody     = errors.New("nil resource body")
	errResourceLen        = errors.New("insufficient data for resource body length")
	errSegTooLong         = errors.New("segment length too long")
	errNameTooLong        = errors.New("name too long")
	errZeroSegLen         = errors.New("zero length segment")
	errResTooLong         = errors.New("resource length too long")
	errTooManyQuestions   = errors.New("too many Questions to pack (>65535)")
	errTooManyAnswers     = errors.New("too many Answers to pack (>65535)")
	errTooManyAuthorities = errors.New("too many Authorities to pack (>65535)")
	errTooManyAdditionals = errors.New("too many Additionals to pack (>65535)")
	errNonCanonicalName   = errors.New("name is not in canonical format (it must end with a .)")
	errStringTooLong      = errors.New("character string exceeds maximum length (255)")
	errCompressedSRV      = errors.New("compressed name in SRV resource data")

	errInvalidResourceBodyLen = errors.New("invalid resource body length")
	errBuilderFinished        = errors.New("builder finished")
	errInvalidLabelLen        = errors.New("invalid label length")
)

type sectionErr struct {
	sec string
	err error
}

func (e *sectionErr) Error() string {
	return e.sec + ": " + e.err.Error()
}

func newSectionErr(sec string, err error) error {
	return &sectionErr{sec: sec, err: err}
}
