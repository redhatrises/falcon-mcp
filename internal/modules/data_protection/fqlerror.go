package data_protection

import (
	"errors"

	dp "github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// The three query endpoints validate FQL filter fields and surface an invalid
// filter as a typed 400 (unlike query APIs that silently return empty). Each
// helper classifies its operation's *BadRequest with errors.As and extracts the
// error details for an FQL-error response. Classifications and policies carry
// []*models.ResponsesError; content patterns carry []*models.MsaAPIError.

// classificationFQLBadRequest reports whether err is a 400-class classification
// query error and, if so, extracts the API error details.
func classificationFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *dp.QueriesClassificationGetV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return responsesErrorDetails(badReq.Payload.Errors), true
}

// policyFQLBadRequest reports whether err is a 400-class policy query error and,
// if so, extracts the API error details.
func policyFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *dp.QueriesPolicyGetV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return responsesErrorDetails(badReq.Payload.Errors), true
}

// contentPatternFQLBadRequest reports whether err is a 400-class content-pattern
// query error and, if so, extracts the API error details.
func contentPatternFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *dp.QueriesContentPatternGetV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// responsesErrorDetails flattens gofalcon ResponsesError values into
// base.FQLErrorDetail. base.FQLErrorDetails handles the MsaAPIError shape used
// by content patterns; ResponsesError is a distinct type with the same Code and
// Message fields, so it needs its own flattener.
func responsesErrorDetails(errs []*models.ResponsesError) []base.FQLErrorDetail {
	details := make([]base.FQLErrorDetail, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var code int32
		if e.Code != nil {
			code = *e.Code
		}
		var msg string
		if e.Message != nil {
			msg = *e.Message
		}
		details = append(details, base.FQLErrorDetail{Code: code, Message: msg})
	}
	return details
}
