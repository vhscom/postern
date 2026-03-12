package api

import (
	"context"
	"fmt"
	"net/http"
)

// GetSubscriptionHistory returns the subscription history for a user.
func (c *Client) GetSubscriptionHistory(ctx context.Context, userID string) (*SubscriptionHistoryResponse, error) {
	var out SubscriptionHistoryResponse
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/ops/subscriptions/%s/history", userID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
