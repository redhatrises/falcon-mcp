package cloud

import (
	"errors"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_detections"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// The CSPM assets, IOM findings, and cloud risks query endpoints validate FQL
// filter fields server-side and surface an unknown field as a typed 400 (unlike
// the container and vulnerability endpoints, which silently return empty). Each
// helper classifies its operation's *BadRequest with errors.As and extracts the
// error details for an FQL-error response. All three carry []*models.MsaAPIError
// on their BadRequest payloads, so base.FQLErrorDetails handles them directly.

// assetsFQLBadRequest reports whether err is a 400-class CSPM assets query error
// and, if so, extracts the API error details.
func assetsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *cloud_security_assets.CloudSecurityAssetsQueriesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// iomFQLBadRequest reports whether err is a 400-class IOM findings query error
// and, if so, extracts the API error details.
func iomFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *cloud_security_detections.CspmEvaluationsIomQueriesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// risksFQLBadRequest reports whether err is a 400-class cloud risks query error
// and, if so, extracts the API error details.
func risksFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *cloud_security.CombinedCloudRisksBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
