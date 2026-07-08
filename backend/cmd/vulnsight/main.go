package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

    "vulnsight.ai/internal/api"
	"vulnsight.ai/internal/db"
)

func main() {
	// Initialize Database
	err := db.InitDB("../vulnsight.db") // Keep it at root for now
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Next.js default port
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-API-Key"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// API Auth Middleware
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for websockets as they handle auth differently in production, or check parameter
			if r.URL.Path == "/api/health" {
				next.ServeHTTP(w, r)
				return
			}
			expectedKey := os.Getenv("VULNSIGHT_API_KEY")
			if expectedKey == "" {
				next.ServeHTTP(w, r) // Disable auth if no key set for local dev ease
				return
			}
			
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != expectedKey {
				http.Error(w, "Unauthorized: Invalid API Key", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// API Routes
	r.Route("/api", func(r chi.Router) {
		r.Use(authMiddleware)
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status": "ok"}`))
		})
		r.Get("/scans", api.GetScansHandler)
		r.Post("/scan", api.StartScanHandler)
		r.Get("/ws/scan/{id}", api.ScanWebSocketHandler)
		r.Get("/report/{id}", api.GenerateReportHandler)
		r.Get("/scan/{id}", api.GetScanByIDHandler)
		r.Get("/models", api.GetModelsHandler)
		r.Get("/diagnostics", api.GetDiagnosticsHandler)
		r.Get("/debug_db", api.DebugDBHandler)
		r.Post("/setup", api.SetupToolsHandler)
		
		// Custom template composer endpoints
		r.Get("/templates", api.ListTemplatesHandler)
		r.Post("/templates/validate", api.ValidateTemplateHandler)
		r.Post("/templates/save", api.SaveTemplateHandler)

		// Wipes local dependencies and resets setup directory
		r.Post("/reset", api.ResetHandler)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🔥 VulnSightAI Engine started on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
