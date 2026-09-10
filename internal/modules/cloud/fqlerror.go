// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
