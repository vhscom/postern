package main

import (
	"encoding/json"
	"net/http"
)

// GET /account/services — lists services with access status for the current user.
func handleServiceList(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)

	rows, err := store.Query(`
		SELECT ms.name, ms.description, ms.host, ms.port,
			CASE WHEN sg.id IS NOT NULL OR ? = 1 THEN 1 ELSE 0 END AS authorized
		FROM mesh_service ms
		LEFT JOIN service_grant sg ON sg.service_id = ms.id AND sg.user_id = ?
		ORDER BY ms.name`,
		claims.UID, claims.UID,
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list services")
		return
	}
	defer rows.Close()

	type service struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
		Host        string  `json:"host"`
		Port        int     `json:"port"`
		Authorized  bool    `json:"authorized"`
	}
	services := make([]service, 0)
	for rows.Next() {
		var s service
		var auth int
		if err := rows.Scan(&s.Name, &s.Description, &s.Host, &s.Port, &auth); err != nil {
			continue
		}
		s.Authorized = auth == 1
		services = append(services, s)
	}
	jsonOK(w, map[string]any{"services": services})
}

// POST /account/services (operator only)
func handleServiceCreate(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims.UID != 1 {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "Only the operator can manage services")
		return
	}

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}
	if body.Name == "" || body.Host == "" || body.Port == 0 {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Name, host, and port are required")
		return
	}

	var desc *string
	if body.Description != "" {
		desc = &body.Description
	}

	_, err := store.Exec(
		"INSERT INTO mesh_service (name, description, host, port) VALUES (?,?,?,?)",
		body.Name, desc, body.Host, body.Port,
	)
	if err != nil {
		if isUniqueViolation(err) {
			respondError(w, r, http.StatusConflict, "SERVICE_EXISTS", "Service name already exists")
			return
		}
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create service")
		return
	}

	jsonCreated(w, map[string]any{"name": body.Name, "host": body.Host, "port": body.Port})
}

// DELETE /account/services/{name} (operator only)
func handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims.UID != 1 {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "Only the operator can manage services")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Service name required")
		return
	}

	result, err := store.Exec("DELETE FROM mesh_service WHERE name = ?", name)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete service")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Service not found")
		return
	}

	jsonOK(w, map[string]any{"ok": true})
}

// POST /account/services/{name}/grant (operator only)
func handleServiceGrant(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims.UID != 1 {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "Only the operator can manage access")
		return
	}

	name := r.PathValue("name")
	var body struct {
		UserID int `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == 0 {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "user_id required")
		return
	}

	var serviceID int
	err := store.QueryRow("SELECT id FROM mesh_service WHERE name = ?", name).Scan(&serviceID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Service not found")
		return
	}

	_, err = store.Exec(
		"INSERT OR IGNORE INTO service_grant (service_id, user_id) VALUES (?,?)",
		serviceID, body.UserID,
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to grant access")
		return
	}

	// Re-sync the user's nodes so they get the service host as a peer
	go notifyNodeSync(body.UserID)

	jsonOK(w, map[string]any{"ok": true, "service": name, "user_id": body.UserID})
}

// DELETE /account/services/{name}/grant/{user_id} (operator only)
func handleServiceRevoke(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims.UID != 1 {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "Only the operator can manage access")
		return
	}

	name := r.PathValue("name")
	userID := r.PathValue("user_id")

	var serviceID int
	err := store.QueryRow("SELECT id FROM mesh_service WHERE name = ?", name).Scan(&serviceID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Service not found")
		return
	}

	store.Exec("DELETE FROM service_grant WHERE service_id = ? AND user_id = ?", serviceID, userID)

	// Re-sync to remove the service host peer
	if uid, ok := numericID(userID); ok {
		go notifyNodeSync(uid)
	}

	jsonOK(w, map[string]any{"ok": true})
}
