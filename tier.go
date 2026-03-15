package main

// --- Tier limits ---

const (
	maxNodesFree = 2
	maxNodesPro  = 10
	maxNodesTeam = 25
)

func getUserTier(db querier, userID int) string {
	var tier string
	err := db.QueryRow(
		"SELECT tier FROM user_subscription WHERE user_id = ? AND (current_period_end IS NULL OR current_period_end > datetime('now'))",
		userID,
	).Scan(&tier)
	if err != nil {
		return "free"
	}
	return tier
}

func nodeLimit(tier string) int {
	switch tier {
	case "pro":
		return maxNodesPro
	case "team":
		return maxNodesTeam
	default:
		return maxNodesFree
	}
}
