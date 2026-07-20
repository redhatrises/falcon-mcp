package exclusions

import (
	"fmt"
	"io"

	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/go-openapi/runtime"
)

// The four exclusion get/create/update operations return heterogeneous gofalcon
// models, and the ML variants carry a codegen bug: ExclusionsExclusionV1.Groups
// is typed []*HostGroupsHostGroupV1, but the live API returns groups as a bare
// []string of host-group IDs, so the generated reader hard-fails with
// "cannot unmarshal string into ... groups" for every ML record that has host
// groups (validated live 2026-07-19; the model type is unchanged on gofalcon
// 542ced95b748, so the mismatch persists).
//
// Rather than special-case ML with one faithful local model and use the typed
// path for the other three, every record-returning operation is routed through a
// raw-capture reader that grabs the 200/201 body and decodes it into
// []map[string]any. This gives the tool one uniform record type across all four
// exclusion kinds, sidesteps the ML model bug, and matches the Python module,
// which returns the raw API dictionaries. get_certificate_details keeps the typed
// path — its model has no such bug.

// rawCaptureReader wraps the generated reader to capture a 2xx body verbatim,
// which the ML generated model cannot decode (see the package note above). It
// returns a valid *OK constructed by mk so the generated client method's success
// type assertion succeeds; non-2xx responses delegate to the wrapped reader so
// 400/403/404/429/500 still surface as gofalcon's typed errors.
type rawCaptureReader struct {
	orig runtime.ClientResponseReader
	body []byte
	mk   func() any
}

// ReadResponse captures any 2xx body into r.body and returns mk()'s placeholder
// OK so the method's type assertion holds; other statuses delegate to the
// wrapped reader, preserving gofalcon's typed error path.
func (r *rawCaptureReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if code := resp.Code(); code >= 200 && code < 300 {
		b, err := io.ReadAll(resp.Body())
		if err != nil {
			return nil, fmt.Errorf("read exclusions response body: %w", err)
		}
		r.body = b
		return r.mk(), nil
	}
	return r.orig.ReadResponse(resp, c)
}

// capture builds a rawCaptureReader for the given placeholder OK constructor and
// the ClientOption that installs it on a gofalcon operation. The returned reader's
// body field holds the captured bytes after the call returns.
func capture(mk func() any) (*rawCaptureReader, func(*runtime.ClientOperation)) {
	r := &rawCaptureReader{mk: mk}
	return r, func(op *runtime.ClientOperation) {
		r.orig = op.Reader
		op.Reader = r
	}
}

// The placeholder OK constructors each success reader's type assertion requires.
// These stand in for the real decoded payload, which the raw-capture reader
// discards in favor of the captured bytes.
var (
	okIOAGet    = func() any { return ioa_exclusions.NewSsIoaExclusionsGetV2OK() }
	okIOACreate = func() any { return ioa_exclusions.NewSsIoaExclusionsCreateV2OK() }
	okIOAUpdate = func() any { return ioa_exclusions.NewSsIoaExclusionsUpdateV2OK() }

	okMLGet    = func() any { return ml_exclusions.NewExclusionsGetV2OK() }
	okMLCreate = func() any { return ml_exclusions.NewExclusionsCreateV2OK() }
	okMLUpdate = func() any { return ml_exclusions.NewExclusionsUpdateV2OK() }

	okSVGet    = func() any { return sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1OK() }
	okSVCreate = func() any { return sensor_visibility_exclusions.NewCreateSVExclusionsV1Created() }
	okSVUpdate = func() any { return sensor_visibility_exclusions.NewUpdateSensorVisibilityExclusionsV1OK() }

	okCBGet    = func() any { return certificate_based_exclusions.NewCbExclusionsGetV1OK() }
	okCBCreate = func() any { return certificate_based_exclusions.NewCbExclusionsCreateV1Created() }
	okCBUpdate = func() any { return certificate_based_exclusions.NewCbExclusionsUpdateV1OK() }
)
