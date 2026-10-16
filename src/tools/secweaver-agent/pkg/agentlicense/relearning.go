package agentlicense

import (
	"context"
	"fmt"
	"secweaver-agent/pkg/learningoperation"
)

// ClaimRelearning reuses device signature/nonce transport, not enrollment or
// browser credentials. A denial is returned only to the optional coordinator.
func (c Client) ClaimRelearning(ctx context.Context, cfg Config, version, operation string, report *learningoperation.Report) (Response, error) {
	cfg = cfg.Normalize()
	if !cfg.DeviceAuthEnabled() || !learningoperation.ValidReport(report) {
		return Response{}, fmt.Errorf("relearning unsupported")
	}
	if err := cfg.Validate(); err != nil {
		return Response{}, err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return Response{}, err
	}
	req := buildRequest(state.EnterpriseID, state, version, "online")
	req.InstallationID = state.InstallationID
	req.BehaviorRelearning = report
	req.RelearningClaim = &struct {
		OperationID string `json:"operation_id"`
	}{operation}
	return c.postSigned(ctx, cfg, "/api/secweaver/v2/agent/relearning/claim", req, state)
}
