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

func TestSubscriptionHistory(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_hist', 'free')")

	// free → pro (checkout)
	handleCheckoutCompleted([]byte(`{"customer":"cus_hist","metadata":{"tier":"pro","user_id":"1"}}`))

	// pro → free (cancellation)
	handleSubscriptionDeleted([]byte(`{"customer":"cus_hist"}`))

	// free → pro (re-subscribe)
	store.Exec("UPDATE user_subscription SET tier = 'free' WHERE stripe_customer_id = 'cus_hist'")
	handleCheckoutCompleted([]byte(`{"customer":"cus_hist","metadata":{"tier":"pro","user_id":"1"}}`))

	rows, err := store.Query(
		"SELECT tier_from, tier_to, reason FROM subscription_history WHERE user_id = 1 ORDER BY id",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	expected := []struct{ from, to, reason string }{
		{"free", "pro", "checkout.completed"},
		{"pro", "free", "subscription.deleted"},
		{"free", "pro", "checkout.completed"},
	}
	i := 0
	for rows.Next() {
		var from, to, reason string
		rows.Scan(&from, &to, &reason)
		if i >= len(expected) {
			t.Fatalf("too many history rows")
		}
		if from != expected[i].from || to != expected[i].to || reason != expected[i].reason {
			t.Errorf("row %d: got %s→%s (%s), want %s→%s (%s)",
				i, from, to, reason, expected[i].from, expected[i].to, expected[i].reason)
		}
		i++
	}
	if i != len(expected) {
		t.Errorf("expected %d history rows, got %d", len(expected), i)
	}
}

func TestSubscriptionHistoryNoOpSkipped(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@x.com', 'hash')")
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'cus_noop', 'free')")

	// free → free should not record
	handleSubscriptionDeleted([]byte(`{"customer":"cus_noop"}`))

	var count int
	store.QueryRow("SELECT COUNT(*) FROM subscription_history WHERE user_id = 1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 history rows for no-op, got %d", count)
	}
}

func TestWebhookBadJSON(t *testing.T) {
	// Should not panic on bad input
	handleCheckoutCompleted([]byte(`not json`))
	handleSubscriptionUpdated([]byte(`not json`))
	handleSubscriptionDeleted([]byte(`not json`))
}
