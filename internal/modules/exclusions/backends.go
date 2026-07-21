package exclusions

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// bodyAs asserts body to the concrete request type T. buildBody and the backend
// are always paired by exclusion_type, so a mismatch is a programming error, not
// a user error — it is reported as one rather than panicking so a wiring bug
// surfaces as a clear message.
func bodyAs[T any](body any) (T, error) {
	typed, ok := body.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("exclusions: internal error: request body is %T, want %T", body, zero)
	}
	return typed, nil
}

// queryArgs carries the search parameters shared across the four exclusion query
// operations. sort is passed already normalized (see normalizeSort).
type queryArgs struct {
	filter string
	sort   string
	limit  int64
	offset *int64
}

// backend abstracts the per-type exclusion operations behind the unified tool
// surface. Each concrete backend wraps one gofalcon sub-client. Record-returning
// operations (get/create/update) return the raw 2xx JSON body rather than a typed
// model, because the ML models carry a codegen bug and the four types' models are
// heterogeneous — see the note in rawclient.go. Shared handler code decodes the
// body once via decodeResources.
type backend interface {
	// query returns the matching exclusion IDs for a search, plus the raw API
	// meta object (pagination/query_time) for verbatim passthrough.
	query(ctx context.Context, a queryArgs) ([]string, any, error)
	// getRaw fetches full records for ids and returns the raw response body.
	getRaw(ctx context.Context, ids []string) ([]byte, error)
	// createRaw sends a prebuilt gofalcon body and returns the raw response body.
	createRaw(ctx context.Context, body any) ([]byte, error)
	// updateRaw sends a prebuilt gofalcon body and returns the raw response body.
	updateRaw(ctx context.Context, body any) ([]byte, error)
	// deleteByIDs deletes the given IDs with an optional audit comment, returning
	// the raw API meta object for verbatim passthrough.
	deleteByIDs(ctx context.Context, ids []string, comment string) (any, error)
	// classifyFQL reports whether err is a 400-class FQL error for this type and,
	// if so, extracts the API error details for an FQL-error response.
	classifyFQL(err error) ([]base.FQLErrorDetail, bool)
}

// ---- IOA backend ---------------------------------------------------------------

// ioaClient is the slice of the gofalcon ioa_exclusions sub-client this module
// consumes. The real sub-client satisfies it directly; tests inject a fake.
type ioaClient interface {
	SsIoaExclusionsSearchV2(*ioa_exclusions.SsIoaExclusionsSearchV2Params, ...ioa_exclusions.ClientOption) (*ioa_exclusions.SsIoaExclusionsSearchV2OK, error)
	SsIoaExclusionsGetV2(*ioa_exclusions.SsIoaExclusionsGetV2Params, ...ioa_exclusions.ClientOption) (*ioa_exclusions.SsIoaExclusionsGetV2OK, error)
	SsIoaExclusionsCreateV2(*ioa_exclusions.SsIoaExclusionsCreateV2Params, ...ioa_exclusions.ClientOption) (*ioa_exclusions.SsIoaExclusionsCreateV2OK, error)
	SsIoaExclusionsUpdateV2(*ioa_exclusions.SsIoaExclusionsUpdateV2Params, ...ioa_exclusions.ClientOption) (*ioa_exclusions.SsIoaExclusionsUpdateV2OK, error)
	SsIoaExclusionsDeleteV2(*ioa_exclusions.SsIoaExclusionsDeleteV2Params, ...ioa_exclusions.ClientOption) (*ioa_exclusions.SsIoaExclusionsDeleteV2OK, error)
}

type ioaBackend struct{ c ioaClient }

func (b ioaBackend) query(ctx context.Context, a queryArgs) ([]string, any, error) {
	p := ioa_exclusions.NewSsIoaExclusionsSearchV2ParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.SsIoaExclusionsSearchV2(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b ioaBackend) getRaw(ctx context.Context, ids []string) ([]byte, error) {
	p := ioa_exclusions.NewSsIoaExclusionsGetV2ParamsWithContext(ctx)
	p.Ids = ids
	r, opt := capture(okIOAGet)
	if _, err := b.c.SsIoaExclusionsGetV2(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b ioaBackend) createRaw(ctx context.Context, body any) ([]byte, error) {
	typed, err := bodyAs[*models.DomainSsIoaExclusionsCreateReqV2](body)
	if err != nil {
		return nil, err
	}
	p := ioa_exclusions.NewSsIoaExclusionsCreateV2ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okIOACreate)
	if _, err := b.c.SsIoaExclusionsCreateV2(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b ioaBackend) updateRaw(ctx context.Context, body any) ([]byte, error) {
	typed, err := bodyAs[*models.DomainSsIoaExclusionsUpdateReqV2](body)
	if err != nil {
		return nil, err
	}
	p := ioa_exclusions.NewSsIoaExclusionsUpdateV2ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okIOAUpdate)
	if _, err := b.c.SsIoaExclusionsUpdateV2(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b ioaBackend) deleteByIDs(ctx context.Context, ids []string, comment string) (any, error) {
	p := ioa_exclusions.NewSsIoaExclusionsDeleteV2ParamsWithContext(ctx)
	p.Ids = ids
	if comment != "" {
		p.Comment = &comment
	}
	resp, err := b.c.SsIoaExclusionsDeleteV2(p)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Payload == nil {
		return nil, nil
	}
	return resp.Payload.Meta, nil
}

// classifyFQL always reports false: the IOA search operation declares no typed
// 400 response, so a bad filter surfaces as a generic runtime error handled by
// base.APIError rather than an FQL-error data result.
func (b ioaBackend) classifyFQL(error) ([]base.FQLErrorDetail, bool) { return nil, false }

// ---- ML backend ----------------------------------------------------------------

type mlClient interface {
	ExclusionsSearchV2(*ml_exclusions.ExclusionsSearchV2Params, ...ml_exclusions.ClientOption) (*ml_exclusions.ExclusionsSearchV2OK, error)
	ExclusionsGetV2(*ml_exclusions.ExclusionsGetV2Params, ...ml_exclusions.ClientOption) (*ml_exclusions.ExclusionsGetV2OK, error)
	ExclusionsCreateV2(*ml_exclusions.ExclusionsCreateV2Params, ...ml_exclusions.ClientOption) (*ml_exclusions.ExclusionsCreateV2OK, error)
	ExclusionsUpdateV2(*ml_exclusions.ExclusionsUpdateV2Params, ...ml_exclusions.ClientOption) (*ml_exclusions.ExclusionsUpdateV2OK, error)
	ExclusionsDeleteV2(*ml_exclusions.ExclusionsDeleteV2Params, ...ml_exclusions.ClientOption) (*ml_exclusions.ExclusionsDeleteV2OK, error)
}

type mlBackend struct{ c mlClient }

func (b mlBackend) query(ctx context.Context, a queryArgs) ([]string, any, error) {
	p := ml_exclusions.NewExclusionsSearchV2ParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.ExclusionsSearchV2(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b mlBackend) getRaw(ctx context.Context, ids []string) ([]byte, error) {
	p := ml_exclusions.NewExclusionsGetV2ParamsWithContext(ctx)
	p.Ids = ids
	r, opt := capture(okMLGet)
	if _, err := b.c.ExclusionsGetV2(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b mlBackend) createRaw(ctx context.Context, body any) ([]byte, error) {
	typed, err := bodyAs[*models.DomainExclusionsCreateReqV2](body)
	if err != nil {
		return nil, err
	}
	p := ml_exclusions.NewExclusionsCreateV2ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okMLCreate)
	if _, err := b.c.ExclusionsCreateV2(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b mlBackend) updateRaw(ctx context.Context, body any) ([]byte, error) {
	// ML update body is the SINGULAR DomainExclusionUpdateReqV2, not a wrapper.
	typed, err := bodyAs[*models.DomainExclusionUpdateReqV2](body)
	if err != nil {
		return nil, err
	}
	p := ml_exclusions.NewExclusionsUpdateV2ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okMLUpdate)
	if _, err := b.c.ExclusionsUpdateV2(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b mlBackend) deleteByIDs(ctx context.Context, ids []string, comment string) (any, error) {
	p := ml_exclusions.NewExclusionsDeleteV2ParamsWithContext(ctx)
	p.Ids = ids
	if comment != "" {
		p.Comment = &comment
	}
	resp, err := b.c.ExclusionsDeleteV2(p)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Payload == nil {
		return nil, nil
	}
	return resp.Payload.Meta, nil
}

// classifyFQL always reports false: the ML search operation declares no typed 400
// response (see ioaBackend.classifyFQL).
func (b mlBackend) classifyFQL(error) ([]base.FQLErrorDetail, bool) { return nil, false }

// ---- Sensor Visibility backend -------------------------------------------------

type svClient interface {
	QuerySensorVisibilityExclusionsV1(*sensor_visibility_exclusions.QuerySensorVisibilityExclusionsV1Params, ...sensor_visibility_exclusions.ClientOption) (*sensor_visibility_exclusions.QuerySensorVisibilityExclusionsV1OK, error)
	GetSensorVisibilityExclusionsV1(*sensor_visibility_exclusions.GetSensorVisibilityExclusionsV1Params, ...sensor_visibility_exclusions.ClientOption) (*sensor_visibility_exclusions.GetSensorVisibilityExclusionsV1OK, error)
	CreateSVExclusionsV1(*sensor_visibility_exclusions.CreateSVExclusionsV1Params, ...sensor_visibility_exclusions.ClientOption) (*sensor_visibility_exclusions.CreateSVExclusionsV1Created, error)
	UpdateSensorVisibilityExclusionsV1(*sensor_visibility_exclusions.UpdateSensorVisibilityExclusionsV1Params, ...sensor_visibility_exclusions.ClientOption) (*sensor_visibility_exclusions.UpdateSensorVisibilityExclusionsV1OK, error)
	DeleteSensorVisibilityExclusionsV1(*sensor_visibility_exclusions.DeleteSensorVisibilityExclusionsV1Params, ...sensor_visibility_exclusions.ClientOption) (*sensor_visibility_exclusions.DeleteSensorVisibilityExclusionsV1OK, error)
}

type svBackend struct{ c svClient }

func (b svBackend) query(ctx context.Context, a queryArgs) ([]string, any, error) {
	p := sensor_visibility_exclusions.NewQuerySensorVisibilityExclusionsV1ParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QuerySensorVisibilityExclusionsV1(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b svBackend) getRaw(ctx context.Context, ids []string) ([]byte, error) {
	p := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	p.Ids = ids
	r, opt := capture(okSVGet)
	if _, err := b.c.GetSensorVisibilityExclusionsV1(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b svBackend) createRaw(ctx context.Context, body any) ([]byte, error) {
	// SV create body is the FLAT SvExclusionsCreateReqV1 (single object, no wrapper).
	typed, err := bodyAs[*models.SvExclusionsCreateReqV1](body)
	if err != nil {
		return nil, err
	}
	p := sensor_visibility_exclusions.NewCreateSVExclusionsV1ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okSVCreate)
	if _, err := b.c.CreateSVExclusionsV1(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b svBackend) updateRaw(ctx context.Context, body any) ([]byte, error) {
	typed, err := bodyAs[*models.SvExclusionsUpdateReqV1](body)
	if err != nil {
		return nil, err
	}
	p := sensor_visibility_exclusions.NewUpdateSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okSVUpdate)
	if _, err := b.c.UpdateSensorVisibilityExclusionsV1(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b svBackend) deleteByIDs(ctx context.Context, ids []string, comment string) (any, error) {
	p := sensor_visibility_exclusions.NewDeleteSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	p.Ids = ids
	if comment != "" {
		p.Comment = &comment
	}
	resp, err := b.c.DeleteSensorVisibilityExclusionsV1(p)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Payload == nil {
		return nil, nil
	}
	return resp.Payload.Meta, nil
}

func (b svBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *sensor_visibility_exclusions.QuerySensorVisibilityExclusionsV1BadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// ---- Certificate-Based backend -------------------------------------------------

type cbClient interface {
	CbExclusionsQueryV1(*certificate_based_exclusions.CbExclusionsQueryV1Params, ...certificate_based_exclusions.ClientOption) (*certificate_based_exclusions.CbExclusionsQueryV1OK, error)
	CbExclusionsGetV1(*certificate_based_exclusions.CbExclusionsGetV1Params, ...certificate_based_exclusions.ClientOption) (*certificate_based_exclusions.CbExclusionsGetV1OK, error)
	CbExclusionsCreateV1(*certificate_based_exclusions.CbExclusionsCreateV1Params, ...certificate_based_exclusions.ClientOption) (*certificate_based_exclusions.CbExclusionsCreateV1Created, error)
	CbExclusionsUpdateV1(*certificate_based_exclusions.CbExclusionsUpdateV1Params, ...certificate_based_exclusions.ClientOption) (*certificate_based_exclusions.CbExclusionsUpdateV1OK, error)
	CbExclusionsDeleteV1(*certificate_based_exclusions.CbExclusionsDeleteV1Params, ...certificate_based_exclusions.ClientOption) (*certificate_based_exclusions.CbExclusionsDeleteV1OK, error)
	CertificatesGetV1(*certificate_based_exclusions.CertificatesGetV1Params, ...certificate_based_exclusions.ClientOption) (*certificate_based_exclusions.CertificatesGetV1OK, error)
}

type cbBackend struct{ c cbClient }

func (b cbBackend) query(ctx context.Context, a queryArgs) ([]string, any, error) {
	p := certificate_based_exclusions.NewCbExclusionsQueryV1ParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.CbExclusionsQueryV1(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b cbBackend) getRaw(ctx context.Context, ids []string) ([]byte, error) {
	p := certificate_based_exclusions.NewCbExclusionsGetV1ParamsWithContext(ctx)
	p.Ids = ids
	r, opt := capture(okCBGet)
	if _, err := b.c.CbExclusionsGetV1(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b cbBackend) createRaw(ctx context.Context, body any) ([]byte, error) {
	typed, err := bodyAs[*models.APICertBasedExclusionsCreateReqV1](body)
	if err != nil {
		return nil, err
	}
	p := certificate_based_exclusions.NewCbExclusionsCreateV1ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okCBCreate)
	if _, err := b.c.CbExclusionsCreateV1(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b cbBackend) updateRaw(ctx context.Context, body any) ([]byte, error) {
	typed, err := bodyAs[*models.APICertBasedExclusionsUpdateReqV1](body)
	if err != nil {
		return nil, err
	}
	p := certificate_based_exclusions.NewCbExclusionsUpdateV1ParamsWithContext(ctx)
	p.Body = typed
	r, opt := capture(okCBUpdate)
	if _, err := b.c.CbExclusionsUpdateV1(p, opt); err != nil {
		return nil, err
	}
	return r.body, nil
}

func (b cbBackend) deleteByIDs(ctx context.Context, ids []string, comment string) (any, error) {
	p := certificate_based_exclusions.NewCbExclusionsDeleteV1ParamsWithContext(ctx)
	p.Ids = ids
	if comment != "" {
		p.Comment = &comment
	}
	resp, err := b.c.CbExclusionsDeleteV1(p)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Payload == nil {
		return nil, nil
	}
	return resp.Payload.Meta, nil
}

func (b cbBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *certificate_based_exclusions.CbExclusionsQueryV1BadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// applyQuery copies the shared query args onto an operation's parameter pointers.
// Filter and offset are only set when meaningful so unset optionals stay nil.
func applyQuery(a queryArgs, filter **string, sort **string, limit **int64, offset **int64) {
	*limit = &a.limit
	if a.filter != "" {
		*filter = &a.filter
	}
	if a.sort != "" {
		*sort = &a.sort
	}
	if a.offset != nil {
		*offset = a.offset
	}
}
