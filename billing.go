package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/stripe/stripe-go/v82"
	portalsession "github.com/stripe/stripe-go/v82/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/webhook"
)

func initStripe() {
	stripe.Key = cfg.StripeSecretKey
}

// POST /account/billing/checkout
func handleBillingCheckout(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)

	var body struct {
		Tier string `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	priceID := tierToPriceID(body.Tier)
	if priceID == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid or unconfigured tier")
		return
	}

	customerID, err := getOrCreateStripeCustomer(claims.UID)
	if err != nil {
		logError("billing.customer", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to set up billing")
		return
	}

	params := &stripe.CheckoutSessionParams{
		Customer:          stripe.String(customerID),
		Mode:              stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL:        stripe.String(cfg.BaseURL + "/#billing-success"),
		CancelURL:         stripe.String(cfg.BaseURL + "/#billing-cancel"),
		ClientReferenceID: stripe.String(strconv.Itoa(claims.UID)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{Price: stripe.String(priceID), Quantity: stripe.Int64(1)},
		},
	}
	params.AddMetadata("tier", body.Tier)
	params.AddMetadata("user_id", strconv.Itoa(claims.UID))

	s, err := checkoutsession.New(params)
	if err != nil {
		logError("billing.checkout", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create checkout session")
		return
	}

	emitEvent("billing.checkout", clientIP(r), claims.UID, r.UserAgent(), 200,
		map[string]any{"tier": body.Tier})
	jsonOK(w, map[string]any{"url": s.URL})
}

// POST /account/billing/portal
func handleBillingPortal(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)

	var customerID string
	err := store.QueryRow(
		"SELECT stripe_customer_id FROM user_subscription WHERE user_id = ?",
		claims.UID,
	).Scan(&customerID)
	if err != nil || customerID == "" {
		respondError(w, r, http.StatusNotFound, "NO_SUBSCRIPTION", "No billing account found")
		return
	}

	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(customerID),
		ReturnURL: stripe.String(cfg.BaseURL + "/#billing"),
	}
	s, err := portalsession.New(params)
	if err != nil {
		logError("billing.portal", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create portal session")
		return
	}

	jsonOK(w, map[string]any{"url": s.URL})
}

// POST /webhooks/stripe — unauthenticated, signature-verified
func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), cfg.StripeWebhookSecret)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch event.Type {
	case "checkout.session.completed":
		handleCheckoutCompleted(event.Data.Raw)
	case "customer.subscription.updated":
		handleSubscriptionUpdated(event.Data.Raw)
	case "customer.subscription.deleted":
		handleSubscriptionDeleted(event.Data.Raw)
	}

	w.WriteHeader(http.StatusOK)
}

func handleCheckoutCompleted(raw json.RawMessage) {
	var session struct {
		Customer string            `json:"customer"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &session); err != nil {
		logError("billing.webhook.checkout", err)
		return
	}

	tier := session.Metadata["tier"]
	if tier == "" {
		tier = "pro"
	}
	userIDStr := session.Metadata["user_id"]
	userID, _ := strconv.Atoi(userIDStr)

	recordTierChange(session.Customer, tier, "checkout.completed")

	_, err := store.Exec(
		"UPDATE user_subscription SET tier = ?, updated_at = datetime('now') WHERE stripe_customer_id = ?",
		tier, session.Customer,
	)
	if err != nil {
		logError("billing.webhook.activate", err)
		return
	}
	emitEvent("billing.activated", "", userID, "", 200, map[string]any{"tier": tier})
}

func handleSubscriptionUpdated(raw json.RawMessage) {
	var sub struct {
		Customer         string `json:"customer"`
		CurrentPeriodEnd int64  `json:"current_period_end"`
		Status           string `json:"status"`
	}
	if err := json.Unmarshal(raw, &sub); err != nil {
		logError("billing.webhook.sub_update", err)
		return
	}

	if sub.Status != "active" && sub.Status != "trialing" {
		recordTierChange(sub.Customer, "free", "subscription."+sub.Status)
		if _, err := store.Exec(
			"UPDATE user_subscription SET tier = 'free', current_period_end = datetime(?, 'unixepoch'), updated_at = datetime('now') WHERE stripe_customer_id = ?",
			sub.CurrentPeriodEnd, sub.Customer,
		); err != nil {
			logError("billing.webhook.sub_downgrade", err)
		}
		return
	}
	if _, err := store.Exec(
		"UPDATE user_subscription SET current_period_end = datetime(?, 'unixepoch'), updated_at = datetime('now') WHERE stripe_customer_id = ?",
		sub.CurrentPeriodEnd, sub.Customer,
	); err != nil {
		logError("billing.webhook.sub_renew", err)
	}
}

func handleSubscriptionDeleted(raw json.RawMessage) {
	var sub struct {
		Customer string `json:"customer"`
	}
	if err := json.Unmarshal(raw, &sub); err != nil {
		logError("billing.webhook.sub_delete", err)
		return
	}

	var userID int
	store.QueryRow("SELECT user_id FROM user_subscription WHERE stripe_customer_id = ?", sub.Customer).Scan(&userID)

	recordTierChange(sub.Customer, "free", "subscription.deleted")

	if _, err := store.Exec(
		"UPDATE user_subscription SET tier = 'free', current_period_end = datetime('now'), updated_at = datetime('now') WHERE stripe_customer_id = ?",
		sub.Customer,
	); err != nil {
		logError("billing.webhook.downgrade", err)
		return
	}
	emitEvent("billing.cancelled", "", userID, "", 200, nil)
}

// --- Subscription history ---

func recordTierChange(customerID, tierTo, reason string) {
	var userID int
	var tierFrom string
	err := store.QueryRow(
		"SELECT user_id, tier FROM user_subscription WHERE stripe_customer_id = ?",
		customerID,
	).Scan(&userID, &tierFrom)
	if err != nil || tierFrom == tierTo {
		return
	}
	store.Exec(
		"INSERT INTO subscription_history (user_id, tier_from, tier_to, reason) VALUES (?, ?, ?, ?)",
		userID, tierFrom, tierTo, reason,
	)
}

// --- Helpers ---

func tierToPriceID(tier string) string {
	switch tier {
	case "pro":
		return cfg.StripePriceProID
	case "team":
		return cfg.StripePriceTeamID
	default:
		return ""
	}
}

func getOrCreateStripeCustomer(userID int) (string, error) {
	var customerID string
	err := store.QueryRow("SELECT stripe_customer_id FROM user_subscription WHERE user_id = ?", userID).Scan(&customerID)
	if err == nil && customerID != "" {
		return customerID, nil
	}

	var email string
	store.QueryRow("SELECT email FROM account WHERE id = ?", userID).Scan(&email)

	params := &stripe.CustomerParams{
		Email: stripe.String(email),
	}
	params.AddMetadata("postern_uid", strconv.Itoa(userID))

	c, err := customer.New(params)
	if err != nil {
		return "", err
	}

	_, err = store.Exec(
		"INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (?, ?, 'free') ON CONFLICT(user_id) DO UPDATE SET stripe_customer_id = excluded.stripe_customer_id",
		userID, c.ID,
	)
	if err != nil {
		return "", err
	}
	return c.ID, nil
}
