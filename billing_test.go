package main

import (
	"testing"
)

func TestTierToPriceID(t *testing.T) {
	cfg = &Config{
		StripePriceProID:  "price_pro_123",
		StripePriceTeamID: "price_team_456",
	}

	if tierToPriceID("pro") != "price_pro_123" {
		t.Error("pro should map to pro price ID")
	}
	if tierToPriceID("team") != "price_team_456" {
		t.Error("team should map to team price ID")
	}
	if tierToPriceID("free") != "" {
		t.Error("free should return empty string")
	}
	if tierToPriceID("invalid") != "" {
		t.Error("invalid should return empty string")
	}
}

func TestWebhookCheckoutCompleted(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	// Create account and subscription
	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_test123', 'free')")

	raw := []byte(`{"customer":"cus_test123","metadata":{"tier":"pro","user_id":"1"}}`)
	handleCheckoutCompleted(raw)

	var tier string
	store.QueryRow("SELECT tier FROM user_subscription WHERE user_id = 1").Scan(&tier)
	if tier != "pro" {
		t.Errorf("expected pro after checkout, got %s", tier)
	}
}

func TestWebhookCheckoutCompletedDefaultTier(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_test456', 'free')")

	// No tier in metadata — should default to pro
	raw := []byte(`{"customer":"cus_test456","metadata":{}}`)
	handleCheckoutCompleted(raw)

	var tier string
	store.QueryRow("SELECT tier FROM user_subscription WHERE user_id = 1").Scan(&tier)
	if tier != "pro" {
		t.Errorf("expected pro default, got %s", tier)
	}
}

func TestWebhookSubscriptionUpdatedActive(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_renew', 'pro')")

	raw := []byte(`{"customer":"cus_renew","current_period_end":1800000000,"status":"active"}`)
	handleSubscriptionUpdated(raw)

	var tier string
	store.QueryRow("SELECT tier FROM user_subscription WHERE stripe_customer_id = 'cus_renew'").Scan(&tier)
	if tier != "pro" {
		t.Errorf("active subscription should keep tier, got %s", tier)
	}

	var periodEnd string
	store.QueryRow("SELECT current_period_end FROM user_subscription WHERE stripe_customer_id = 'cus_renew'").Scan(&periodEnd)
	if periodEnd == "" {
		t.Error("current_period_end should be set")
	}
}

func TestWebhookSubscriptionUpdatedPastDue(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_pastdue', 'pro')")

	raw := []byte(`{"customer":"cus_pastdue","current_period_end":1800000000,"status":"past_due"}`)
	handleSubscriptionUpdated(raw)

	var tier string
	store.QueryRow("SELECT tier FROM user_subscription WHERE stripe_customer_id = 'cus_pastdue'").Scan(&tier)
	if tier != "free" {
		t.Errorf("past_due should downgrade to free, got %s", tier)
	}
}

func TestWebhookSubscriptionDeleted(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_cancel', 'pro')")

	raw := []byte(`{"customer":"cus_cancel"}`)
	handleSubscriptionDeleted(raw)

	var tier string
	store.QueryRow("SELECT tier FROM user_subscription WHERE stripe_customer_id = 'cus_cancel'").Scan(&tier)
	if tier != "free" {
		t.Errorf("deleted subscription should downgrade to free, got %s", tier)
	}
}

func TestWebhookBadJSON(t *testing.T) {
	// Should not panic on bad input
	handleCheckoutCompleted([]byte(`not json`))
	handleSubscriptionUpdated([]byte(`not json`))
	handleSubscriptionDeleted([]byte(`not json`))
}
