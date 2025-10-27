package main

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
    _ "github.com/lib/pq"
    "github.com/joho/godotenv"
)

func mustGetEnv(key string) string {
    value, ok := os.LookupEnv(key)
    if !ok || value == "" {
        log.Fatalf("❌ Missing required environment variable: %s", key)
    }
    return value
}

type JSONDate time.Time

func (jd *JSONDate) UnmarshalJSON(data []byte) error {
    var dateStr string
    if err := json.Unmarshal(data, &dateStr); err != nil {
        return fmt.Errorf("invalid date format: %w", err)
    }
    if dateStr == "" {
        *jd = JSONDate(time.Time{})
        return nil
    }
    t, err := time.Parse("2006-01-02", dateStr)
    if err != nil {
        t, err = time.Parse(time.RFC3339, dateStr)
        if err != nil {
             return fmt.Errorf("cannot parse %q as YYYY-MM-DD or RFC3339: %w", dateStr, err)
        }
    }
    *jd = JSONDate(t)
    return nil
}

func (jd JSONDate) MarshalJSON() ([]byte, error) {
	t := time.Time(jd)
	if t.IsZero() {
		return json.Marshal(nil)
	}
	return json.Marshal(t.Format("2006-01-02"))
}

func (jd JSONDate) Value() (driver.Value, error) {
    t := time.Time(jd)
    if t.IsZero() {
        return nil, nil
    }
	return t, nil
}

func (jd *JSONDate) Scan(value interface{}) error {
	if value == nil {
		*jd = JSONDate(time.Time{})
		return nil
	}
	if t, ok := value.(time.Time); ok {
		*jd = JSONDate(t)
		return nil
	}
	return fmt.Errorf("cannot scan %T into JSONDate", value)
}

type JSONNullTime struct {
	sql.NullTime
}

func (v *JSONNullTime) UnmarshalJSON(data []byte) error {
	var dateStr *string
	if err := json.Unmarshal(data, &dateStr); err != nil {
		return err
	}
	if dateStr == nil || *dateStr == "" {
		v.Valid = false
		return nil
	}
	t, err := time.Parse("2006-01-02", *dateStr)
	if err != nil {
         t, err = time.Parse(time.RFC3339, *dateStr)
         if err != nil {
		    return fmt.Errorf("cannot parse %q as YYYY-MM-DD or RFC3339: %w", *dateStr, err)
         }
	}
	v.Valid = true
	v.Time = t
	return nil
}

func (v JSONNullTime) MarshalJSON() ([]byte, error) {
	if !v.Valid {
		return json.Marshal(nil)
	}
	return json.Marshal(v.Time.Format("2006-01-02"))
}

type User struct {
	ID          int            `json:"id"`
	Username    string         `json:"username"`
	Password    string         `json:"-"`
	Role        string         `json:"role"`
	CompanyName sql.NullString `json:"companyName"`
	VendorType  sql.NullString `json:"vendorType"` 
}

type UserRequest struct {
	Username    string         `json:"username" binding:"required"`
	Password    string         `json:"password,omitempty"`
	Role        string         `json:"role" binding:"required"`
	CompanyName sql.NullString `json:"companyName"`
	VendorType  sql.NullString `json:"vendorType"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Project struct {
    ID                        int          `json:"id"`
    ProjectName               string       `json:"projectName"`
    WBS                       string       `json:"wbs"`
    Category                  string       `json:"category"`
    Quantity                  int          `json:"quantity"`
    VendorPanel               string       `json:"vendorPanel"`
    VendorBusbar              string       `json:"vendorBusbar"`
    PanelProgress             int          `json:"panelProgress"`
    StatusBusbar              string       `json:"statusBusbar"`
    CreatedAt                 time.Time    `json:"createdAt"`
    UpdatedAt                 time.Time    `json:"updatedAt"`
    PlanStart                 JSONDate     `json:"planStart"` 
    FatStart                  JSONNullTime `json:"fatStart"`
    PlanDeliveryBasicKitPanel JSONNullTime `json:"planDeliveryBasicKitPanel"`
    PlanDeliveryBasicKitBusbar JSONNullTime `json:"planDeliveryBasicKitBusbar"`
    ActualDeliveryBasicKitPanel JSONNullTime `json:"actualDeliveryBasicKitPanel"`
    ActualDeliveryBasicKitBusbar JSONNullTime `json:"actualDeliveryBasicKitBusbar"`
    PlanDeliveryAccessoriesPanel JSONNullTime `json:"planDeliveryAccessoriesPanel"`
    PlanDeliveryAccessoriesBusbar JSONNullTime `json:"planDeliveryAccessoriesBusbar"`
    ActualDeliveryAccessoriesPanel JSONNullTime `json:"actualDeliveryAccessoriesPanel"`
    ActualDeliveryAccessoriesBusbar JSONNullTime `json:"actualDeliveryAccessoriesBusbar"`
}

type DashboardData struct {
    TotalProjects   int            `json:"totalProjects"`
    AverageProgress float64        `json:"averageProgress"`
    ActiveVendors   int            `json:"activeVendors"`
    UpcomingEvents  []ProjectEvent `json:"upcomingEvents"`
    BusbarStatus    []BusbarStat   `json:"busbarStatus"`
}

type ProjectEvent struct {
    ProjectName string `json:"projectName"`
    EventType   string `json:"eventType"`
    EventDate   string `json:"eventDate"`
}

type BusbarStat struct {
    Status string `json:"status"`
    Count  int    `json:"count"`
}

var db *sql.DB

func main() {
    if err := godotenv.Load(); err != nil {
        log.Println("⚠️  No .env file found — assuming production environment")
    }

    connStr := fmt.Sprintf(
        "host=%s user=%s password=%s dbname=%s port=%s sslmode=require",
        mustGetEnv("POSTGRES_HOST"),
        mustGetEnv("POSTGRES_USER"),
        mustGetEnv("POSTGRES_PASSWORD"),
        mustGetEnv("POSTGRES_DB"),
        mustGetEnv("POSTGRES_PORT"),
    )

    var err error
    db, err = sql.Open("postgres", connStr) 
    if err != nil {
        log.Fatal("❌ Failed to open database connection:", err)
    }
    defer db.Close()

    if err := db.Ping(); err != nil {
        log.Fatal("❌ Database ping failed:", err)
    }

    log.Println("✅ Connected to PostgreSQL successfully!")

    sqlFile, err := os.ReadFile("init.sql")
    if err != nil {
        fmt.Println("Skipping init.sql:", err)
    } else {
        _, err = db.Exec(string(sqlFile))
        if err != nil {
            fmt.Println("Init.sql execution error:", err)
        } else {
            fmt.Println("Database initialized.")
        }
    }
	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "X-User-Role"}
	router.Use(cors.New(config))
	api := router.Group("/api")
	{
		api.POST("/login", loginUser)

		projects := api.Group("/projects")
		projects.Use(AuthMiddleware())

		projects.POST("/", createProject)
		projects.POST("/bulk", createBulkProjects)
		projects.GET("/", getProjects)
		projects.GET("/:id", getProjectByID)
		projects.PUT("/:id", updateProject)
		projects.DELETE("/:id", deleteProject)
		projects.PATCH("/:id/start-panel-delivery", startPanelDelivery)
		projects.PATCH("/:id/start-accessories-delivery", startAccessoriesDelivery)

		api.GET("/dashboard", getDashboardData)
		
		api.GET("/companies", AuthMiddleware(), getCompanies)
        api.GET("/vendor-types", AuthMiddleware(), getVendorTypes)

		users := api.Group("/users")
		users.Use(AuthMiddleware())    
		users.Use(AdminAuthMiddleware())
		{
			users.GET("/", getUsers)
			users.POST("/", createUser)
			users.PUT("/:id", updateUser)
			users.DELETE("/:id", deleteUser)
		}
	}
    router.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "API running"})
    })

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080" 
    }

    fmt.Printf("🚀 Server Go berjalan di port %s\n", port)
    if err := router.Run(":" + port); err != nil {
        log.Fatal("❌ Failed to start server:", err)
    }

}

func loginUser(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username dan password dibutuhkan"})
		return
	}

	var user User
	err := db.QueryRow(
		"SELECT id, username, password, role, company_name, vendor_type FROM users WHERE username = $1",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.CompanyName, &user.VendorType) 

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
			return
		}
		log.Printf("Error querying user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal login"})
		return
	}

	if user.Password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"username":    user.Username,
		"role":        user.Role,
		"companyName": user.CompanyName.String,
		"vendorType":  user.VendorType.String,
	})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetHeader("X-User-Role")
		if role == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Header X-User-Role dibutuhkan"})
			return
		}
		c.Next()
	}
}

func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetHeader("X-User-Role")
		if role != "Admin" && role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Hanya Admin yang diizinkan"})
			return
		}
		c.Next()
	}
}

func getUsers(c *gin.Context) {
	rows, err := db.Query("SELECT id, username, role, company_name, vendor_type FROM users ORDER BY username")
	if err != nil {
		log.Printf("Error querying users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data pengguna"})
		return
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CompanyName, &u.VendorType); err != nil {
			log.Printf("Error scanning user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data pengguna"})
			return
		}
		users = append(users, u)
	}

	c.JSON(http.StatusOK, users)
}

func createUser(c *gin.Context) {
	var req UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password dibutuhkan untuk pengguna baru"})
		return
	}

	if req.Role == "External/Vendor" && (!req.CompanyName.Valid || req.CompanyName.String == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nama Perusahaan (Company Name) dibutuhkan untuk role Vendor"})
		return
	}

	var newID int
	err := db.QueryRow(
		`INSERT INTO users (username, password, role, company_name, vendor_type)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		req.Username, req.Password, req.Role, req.CompanyName, req.VendorType,
	).Scan(&newID)

	if err != nil {
		log.Printf("Error creating user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat pengguna: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": newID, "username": req.Username, "role": req.Role, "companyName": req.CompanyName, "vendorType": req.VendorType})
}

func updateUser(c *gin.Context) {
	id := c.Param("id")
	var req UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if req.Role == "External/Vendor" && (!req.CompanyName.Valid || req.CompanyName.String == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nama Perusahaan (Company Name) dibutuhkan untuk role Vendor"})
		return
	}

	if req.Password != "" {
		_, err := db.Exec(
			`UPDATE users SET username=$1, role=$2, company_name=$3, vendor_type=$4, password=$5
			 WHERE id=$6`,
			req.Username, req.Role, req.CompanyName, req.VendorType, req.Password, id,
		)
		if err != nil {
			log.Printf("Error updating user with password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update pengguna: " + err.Error()})
			return
		}
	} else {
		_, err := db.Exec(
			`UPDATE users SET username=$1, role=$2, company_name=$3, vendor_type=$4
			 WHERE id=$5`,
			req.Username, req.Role, req.CompanyName, req.VendorType, id,
		)
		if err != nil {
			log.Printf("Error updating user w/o password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update pengguna: " + err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Pengguna berhasil diupdate", "id": id, "username": req.Username, "role": req.Role})
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")

	_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus pengguna"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Pengguna berhasil dihapus"})
}

func getDashboardData(c *gin.Context) {
    var data DashboardData

    err := db.QueryRow("SELECT COUNT(*) FROM projects").Scan(&data.TotalProjects)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil total proyek"})
        return
    }
    
    err = db.QueryRow("SELECT COALESCE(AVG(panel_progress), 0) FROM projects").Scan(&data.AverageProgress)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil progres rata-rata"})
        return
    }

    err = db.QueryRow("SELECT COUNT(DISTINCT vendor) FROM (SELECT vendor_panel AS vendor FROM projects UNION SELECT vendor_busbar AS vendor FROM projects) AS vendors WHERE vendor IS NOT NULL AND vendor != ''").Scan(&data.ActiveVendors)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil vendor aktif"})
        return
    }

    eventRows, err := db.Query(`
        SELECT project_name, 'Jadwal Mulai Proyek' AS event_type, plan_start AS event_date 
        FROM projects 
        WHERE plan_start BETWEEN NOW() AND NOW() + interval '7 day'
        
        UNION
        
        SELECT project_name, 'Pengiriman Basic Kit Panel (Plan)' AS event_type, plan_delivery_basic_kit_panel AS event_date 
        FROM projects 
        WHERE plan_delivery_basic_kit_panel BETWEEN NOW() AND NOW() + interval '7 day'

        UNION

        SELECT project_name, 'Pengiriman Basic Kit Busbar (Plan)' AS event_type, plan_delivery_basic_kit_busbar AS event_date 
        FROM projects 
        WHERE plan_delivery_basic_kit_busbar BETWEEN NOW() AND NOW() + interval '7 day'

        UNION

        SELECT project_name, 'Pengiriman Accessories Panel (Plan)' AS event_type, plan_delivery_accessories_panel AS event_date 
        FROM projects 
        WHERE plan_delivery_accessories_panel BETWEEN NOW() AND NOW() + interval '7 day'
        
        UNION

        SELECT project_name, 'Pengiriman Accessories Busbar (Plan)' AS event_type, plan_delivery_accessories_busbar AS event_date 
        FROM projects 
        WHERE plan_delivery_accessories_busbar BETWEEN NOW() AND NOW() + interval '7 day'

        ORDER BY event_date ASC
    `)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil event mendatang"})
        return
    }
    defer eventRows.Close()
    for eventRows.Next() {
        var pe ProjectEvent
        var eventDate time.Time
        if err := eventRows.Scan(&pe.ProjectName, &pe.EventType, &eventDate); err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data event"})
            return
        }
        pe.EventDate = eventDate.Format("2006-01-02")
        data.UpcomingEvents = append(data.UpcomingEvents, pe)
    }

    busbarRows, err := db.Query("SELECT status_busbar, COUNT(*) FROM projects GROUP BY status_busbar")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil status busbar"})
        return
    }
    defer busbarRows.Close()
    for busbarRows.Next() {
        var bs BusbarStat
        if err := busbarRows.Scan(&bs.Status, &bs.Count); err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data status busbar"})
            return
        }
        data.BusbarStatus = append(data.BusbarStatus, bs)
    }

    c.JSON(http.StatusOK, data)
}

func createProject(c *gin.Context) {
    var p Project
    if err := c.ShouldBindJSON(&p); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
        return
    }
    role := c.GetHeader("X-User-Role")
    if role != "Admin" && role != "admin" { 
        c.JSON(http.StatusForbidden, gin.H{"error": "Hanya Admin yang dapat membuat proyek"})
        return
    }

    err := db.QueryRow(
        `INSERT INTO projects (
            project_name, wbs, category, plan_start, quantity, 
            vendor_panel, vendor_busbar, panel_progress, status_busbar, 
            fat_start 
         ) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
        p.ProjectName, p.WBS, p.Category, p.PlanStart, p.Quantity, 
        p.VendorPanel, p.VendorBusbar, p.PanelProgress, p.StatusBusbar,
        p.FatStart, 
    ).Scan(&p.ID)

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat proyek: " + err.Error()})
        return
    }
    c.JSON(http.StatusCreated, p)
}

func createBulkProjects(c *gin.Context) {
	role := c.GetHeader("X-User-Role")
	if role != "Admin" { 
		c.JSON(http.StatusForbidden, gin.H{"error": "Hanya Admin yang dapat menambah proyek massal"})
		return
	}
	var projects []Project
	if err := c.ShouldBindJSON(&projects); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}
	if len(projects) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tidak ada data proyek yang dikirim"})
		return
	}
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi: " + err.Error()})
		return
	}

	stmt, err := tx.Prepare(`
        INSERT INTO projects (
            project_name, wbs, category, plan_start, quantity,
            vendor_panel, vendor_busbar, panel_progress, status_busbar,
            fat_start, 
            plan_delivery_basic_kit_panel, plan_delivery_basic_kit_busbar,
            actual_delivery_basic_kit_panel, actual_delivery_basic_kit_busbar,
            plan_delivery_accessories_panel, plan_delivery_accessories_busbar,
            actual_delivery_accessories_panel, actual_delivery_accessories_busbar
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 
            $11, $12, $13, $14, $15, $16, $17, $18
        )
        ON CONFLICT (wbs) DO UPDATE SET
            project_name = EXCLUDED.project_name,
            category = EXCLUDED.category,
            plan_start = EXCLUDED.plan_start,
            quantity = EXCLUDED.quantity,
            vendor_panel = EXCLUDED.vendor_panel,
            vendor_busbar = EXCLUDED.vendor_busbar,
            panel_progress = EXCLUDED.panel_progress,
            status_busbar = EXCLUDED.status_busbar,
            fat_start = EXCLUDED.fat_start,
            plan_delivery_basic_kit_panel = EXCLUDED.plan_delivery_basic_kit_panel,
            plan_delivery_basic_kit_busbar = EXCLUDED.plan_delivery_basic_kit_busbar,
            actual_delivery_basic_kit_panel = EXCLUDED.actual_delivery_basic_kit_panel,
            actual_delivery_basic_kit_busbar = EXCLUDED.actual_delivery_basic_kit_busbar,
            plan_delivery_accessories_panel = EXCLUDED.plan_delivery_accessories_panel,
            plan_delivery_accessories_busbar = EXCLUDED.plan_delivery_accessories_busbar,
            actual_delivery_accessories_panel = EXCLUDED.actual_delivery_accessories_panel,
            actual_delivery_accessories_busbar = EXCLUDED.actual_delivery_accessories_busbar,
            updated_at = NOW()
    `)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan statement upsert: " + err.Error()})
		return
	}
	defer stmt.Close()

	processedCount := 0
	for _, p := range projects {
		_, err := stmt.Exec(
			p.ProjectName, p.WBS, p.Category, p.PlanStart, p.Quantity,
			p.VendorPanel, p.VendorBusbar, p.PanelProgress, p.StatusBusbar,
			p.FatStart,
			p.PlanDeliveryBasicKitPanel, p.PlanDeliveryBasicKitBusbar,
			p.ActualDeliveryBasicKitPanel, p.ActualDeliveryBasicKitBusbar,
			p.PlanDeliveryAccessoriesPanel, p.PlanDeliveryAccessoriesBusbar,
			p.ActualDeliveryAccessoriesPanel, p.ActualDeliveryAccessoriesBusbar,
		)
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Gagal upsert data proyek '%s': %s", p.ProjectName, err.Error())})
			return
		}
		processedCount++
	}

	err = tx.Commit()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit transaksi: " + err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": fmt.Sprintf("%d data proyek berhasil diproses (ditambah/diupdate).", processedCount)})
}

func getProjects(c *gin.Context) {
	rows, err := db.Query(`
        SELECT 
            id, project_name, wbs, category, quantity, vendor_panel, vendor_busbar, 
            panel_progress, status_busbar, created_at, updated_at,
            plan_start, fat_start, 
            plan_delivery_basic_kit_panel, plan_delivery_basic_kit_busbar,
            actual_delivery_basic_kit_panel, actual_delivery_basic_kit_busbar,
            plan_delivery_accessories_panel, plan_delivery_accessories_busbar,
            actual_delivery_accessories_panel, actual_delivery_accessories_busbar
        FROM projects 
        ORDER BY plan_start ASC
    `)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data proyek: " + err.Error()})
		return
	}
	defer rows.Close()
	projects := make([]Project, 0)
	for rows.Next() {
		var p Project
		if err := rows.Scan(
			&p.ID, &p.ProjectName, &p.WBS, &p.Category, &p.Quantity, &p.VendorPanel, &p.VendorBusbar,
			&p.PanelProgress, &p.StatusBusbar, &p.CreatedAt, &p.UpdatedAt,
			&p.PlanStart, &p.FatStart,
			&p.PlanDeliveryBasicKitPanel, &p.PlanDeliveryBasicKitBusbar,
			&p.ActualDeliveryBasicKitPanel, &p.ActualDeliveryBasicKitBusbar,
			&p.PlanDeliveryAccessoriesPanel, &p.PlanDeliveryAccessoriesBusbar,
			&p.ActualDeliveryAccessoriesPanel, &p.ActualDeliveryAccessoriesBusbar,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data proyek: " + err.Error()})
			return
		}
		projects = append(projects, p)
	}
	c.JSON(http.StatusOK, projects)
}

func getProjectByID(c *gin.Context) {
	id := c.Param("id")
	var p Project
	err := db.QueryRow(`
        SELECT 
            id, project_name, wbs, category, quantity, vendor_panel, vendor_busbar, 
            panel_progress, status_busbar, created_at, updated_at,
            plan_start, fat_start, 
            plan_delivery_basic_kit_panel, plan_delivery_basic_kit_busbar,
            actual_delivery_basic_kit_panel, actual_delivery_basic_kit_busbar,
            plan_delivery_accessories_panel, plan_delivery_accessories_busbar,
            actual_delivery_accessories_panel, actual_delivery_accessories_busbar
        FROM projects WHERE id = $1`, id).Scan(
		&p.ID, &p.ProjectName, &p.WBS, &p.Category, &p.Quantity, &p.VendorPanel, &p.VendorBusbar,
		&p.PanelProgress, &p.StatusBusbar, &p.CreatedAt, &p.UpdatedAt,
		&p.PlanStart, &p.FatStart,
		&p.PlanDeliveryBasicKitPanel, &p.PlanDeliveryBasicKitBusbar,
		&p.ActualDeliveryBasicKitPanel, &p.ActualDeliveryBasicKitBusbar,
		&p.PlanDeliveryAccessoriesPanel, &p.PlanDeliveryAccessoriesBusbar,
		&p.ActualDeliveryAccessoriesPanel, &p.ActualDeliveryAccessoriesBusbar,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Proyek tidak ditemukan"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil proyek"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func updateProject(c *gin.Context) {
	id := c.Param("id")
	role := c.GetHeader("X-User-Role")
	if role == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Anda tidak punya izin untuk update"})
		return
	}
	var p Project
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	_, err := db.Exec(
		`UPDATE projects SET 
            project_name=$1, wbs=$2, category=$3, quantity=$4, 
            vendor_panel=$5, vendor_busbar=$6, panel_progress=$7, status_busbar=$8,
            plan_start=$9, fat_start=$10, 
            plan_delivery_basic_kit_panel=$11, plan_delivery_basic_kit_busbar=$12,
            actual_delivery_basic_kit_panel=$13, actual_delivery_basic_kit_busbar=$14,
            plan_delivery_accessories_panel=$15, plan_delivery_accessories_busbar=$16,
            actual_delivery_accessories_panel=$17, actual_delivery_accessories_busbar=$18,
            updated_at=NOW()
         WHERE id=$19`,
		p.ProjectName, p.WBS, p.Category, p.Quantity,
		p.VendorPanel, p.VendorBusbar, p.PanelProgress, p.StatusBusbar,
		p.PlanStart, p.FatStart,
		p.PlanDeliveryBasicKitPanel, p.PlanDeliveryBasicKitBusbar,
		p.ActualDeliveryBasicKitPanel, p.ActualDeliveryBasicKitBusbar,
		p.PlanDeliveryAccessoriesPanel, p.PlanDeliveryAccessoriesBusbar,
		p.ActualDeliveryAccessoriesPanel, p.ActualDeliveryAccessoriesBusbar,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update proyek: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Proyek berhasil diupdate"})
}

func deleteProject(c *gin.Context) {
	id := c.Param("id")
	role := c.GetHeader("X-User-Role")
	if role != "Admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Hanya Admin yang dapat menghapus proyek"})
		return
	}
	_, err := db.Exec("DELETE FROM projects WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus proyek"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Proyek berhasil dihapus"})
}

func startPanelDelivery(c *gin.Context) {
	id := c.Param("id")

	var planStart time.Time
	err := db.QueryRow("SELECT plan_start FROM projects WHERE id = $1", id).Scan(&planStart)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Proyek tidak ditemukan"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data proyek: " + err.Error()})
		return
	}

	planDeliveryDate := planStart.AddDate(0, 0, 7)

	_, err = db.Exec(`
        UPDATE projects SET 
            plan_delivery_basic_kit_panel = $1, 
            plan_delivery_basic_kit_busbar = $2, 
            panel_progress = 100, 
            status_busbar = 'Done',
            updated_at = NOW()
        WHERE id = $3`, planDeliveryDate, planDeliveryDate, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update proyek: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Proyek diupdate: Pengiriman Basic Kit (Plan) telah dimulai"})
}

func startAccessoriesDelivery(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		FatStart string `json:"fatStart" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	fatDate, err := time.Parse("2006-01-02", req.FatStart)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Format tanggal FAT tidak valid, gunakan YYYY-MM-DD"})
		return
	}

	accessoriesDate := fatDate.AddDate(0, 0, 7)

	_, err = db.Exec(`
        UPDATE projects SET 
            fat_start = $1, 
            plan_delivery_accessories_panel = $2,
            plan_delivery_accessories_busbar = $3,
            updated_at = NOW()
        WHERE id = $4`, fatDate, accessoriesDate, accessoriesDate, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update proyek: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Proyek diupdate: Pengiriman Accessories (Plan) telah dimulai"})
}

func getCompanies(c *gin.Context) {
    rows, err := db.Query("SELECT DISTINCT company_name FROM users WHERE company_name IS NOT NULL AND company_name != '' ORDER BY company_name")
    if err != nil {
        log.Printf("Error querying companies: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar perusahaan"})
        return
    }
    defer rows.Close()

    companies := make([]string, 0)
    for rows.Next() {
        var company string
        if err := rows.Scan(&company); err != nil {
            log.Printf("Error scanning company: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai nama perusahaan"})
            return
        }
        companies = append(companies, company)
    }

    c.JSON(http.StatusOK, companies)
}

func getVendorTypes(c *gin.Context) {
    rows, err := db.Query("SELECT DISTINCT vendor_type FROM users WHERE vendor_type IS NOT NULL AND vendor_type != '' ORDER BY vendor_type")
    if err != nil {
        log.Printf("Error querying vendor types: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar tipe vendor"})
        return
    }
    defer rows.Close()

    types := make([]string, 0)
    for rows.Next() {
        var vtype string
        if err := rows.Scan(&vtype); err != nil {
            log.Printf("Error scanning vendor type: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai tipe vendor"})
            return
        }
        types = append(types, vtype)
    }

    c.JSON(http.StatusOK, types)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}