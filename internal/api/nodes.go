package api

import (
	"context"
	"net/http"
)

// ListNodes returns all nodes, optionally filtered by user ID.
func (c *Client) ListNodes(ctx context.Context, userID string) (*ListNodesResponse, error) {
	path := "/ops/nodes"
	if userID != "" {
		path += "?user_id=" + userID
	}
	var out ListNodesResponse
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
