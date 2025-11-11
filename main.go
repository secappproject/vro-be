package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

func mustGetEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		log.Fatalf("❌ Missing required environment variable: %s", key)
	}
	return value
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

type Vendor struct {
	ID          int       `json:"id"`
	CompanyName string    `json:"companyName" binding:"required"`
	VendorType  string    `json:"vendorType" binding:"required"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Material struct {
	ID                  int           `json:"id"`
	MaterialCode        string        `json:"material" binding:"required"`
	MaterialDescription string        `json:"materialDescription"`
	Location            string        `json:"lokasi"`
	PackQuantity        int           `json:"packQuantity" binding:"required"`
	MaxBinQty           int           `json:"maxBinQty" binding:"required"`
	MinBinQty           int           `json:"minBinQty" binding:"required"`
	VendorCode          string        `json:"vendorCode"`
	CurrentQuantity     int           `json:"currentQuantity"`
	PIC                 string        `json:"pic"`
	ProductType         string        `json:"productType"`
	Bins                []MaterialBin `json:"bins,omitempty"`
}

type MaterialStatusResponse struct {
	PackQuantity      int    `json:"packQuantity"`
	MaxBinQty         int    `json:"maxBinQty"`
	MinBinQty         int    `json:"minBinQty"`
	CurrentQuantity   int    `json:"currentQuantity"`
	ProductType       string `json:"productType"`
	PredictedMovement string `json:"predictedMovement"`
}

type MaterialBin struct {
	ID              int `json:"id"`
	MaterialID      int `json:"materialId"`
	BinSequenceID   int `json:"binSequenceId"`
	MaxBinStock     int `json:"maxBinStock"`
	CurrentBinStock int `json:"currentBinStock"`
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

	router := gin.Default()
	router.RedirectTrailingSlash = true
	config := cors.Config{
		AllowOrigins:     []string{"https://vro-fe.vercel.app", "http://localhost:3000", "http://localhost:3001"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-User-Role"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(config))
	api := router.Group("/api")

	{
		api.POST("/login", loginUser)

		users := api.Group("/users")
		users.Use(AuthMiddleware())
		users.Use(AdminAuthMiddleware())
		{
			users.GET("/", getUsers)
			users.POST("/", createUser)
			users.PUT("/:id", updateUser)
			users.DELETE("/:id", deleteUser)
		}

		api.GET("/vendor-type", getVendorTypes)
		api.GET("/companies", getCompanies)
		vendors := api.Group("/vendors")
		vendors.Use(AuthMiddleware())
		vendors.Use(AdminAuthMiddleware())
		{
			vendors.GET("/", getVendors)
			vendors.POST("/", createVendor)
			vendors.PUT("/:id", updateVendor)
			vendors.DELETE("/:id", deleteVendor)
		}

		materials := api.Group("/materials")
		materials.Use(AuthMiddleware())
		materials.Use(AdminAuthMiddleware())

		{
			materials.GET("/", getMaterials)
			materials.POST("/", createMaterial)
			materials.PUT("/:id", updateMaterial)
			materials.DELETE("/:id", deleteMaterial)
			materials.POST("/scan/auto", scanAutoMaterials)
			materials.GET("/status", getMaterialStatus)
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
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

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

	var newUser User
	err = db.QueryRow(
		"SELECT id, username, role, company_name, vendor_type FROM users WHERE id = $1", newID,
	).Scan(&newUser.ID, &newUser.Username, &newUser.Role, &newUser.CompanyName, &newUser.VendorType)
	if err != nil {
		log.Printf("Error fetching newly created user: %v", err)
		c.JSON(http.StatusCreated, gin.H{"id": newID, "username": req.Username, "role": req.Role, "companyName": req.CompanyName, "vendorType": req.VendorType})
		return
	}

	c.JSON(http.StatusCreated, newUser)
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

func getCompanies(c *gin.Context) {
	rows, err := db.Query("SELECT DISTINCT company_name FROM vendors ORDER BY company_name")
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
	rows, err := db.Query("SELECT DISTINCT vendor_type FROM vendors ORDER BY vendor_type")
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

func getVendors(c *gin.Context) {
	rows, err := db.Query("SELECT id, company_name, vendor_type, created_at, updated_at FROM vendors ORDER BY company_name")
	if err != nil {
		log.Printf("Error querying vendors: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data vendor"})
		return
	}
	defer rows.Close()

	vendors := make([]Vendor, 0)
	for rows.Next() {
		var v Vendor
		if err := rows.Scan(&v.ID, &v.CompanyName, &v.VendorType, &v.CreatedAt, &v.UpdatedAt); err != nil {
			log.Printf("Error scanning vendor: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data vendor"})
			return
		}
		vendors = append(vendors, v)
	}

	c.JSON(http.StatusOK, vendors)
}

func createVendor(c *gin.Context) {
	var v Vendor
	if err := c.ShouldBindJSON(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	err := db.QueryRow(
		`INSERT INTO vendors (company_name, vendor_type)
		 VALUES ($1, $2)
		 RETURNING id, created_at, updated_at`,
		v.CompanyName, v.VendorType,
	).Scan(&v.ID, &v.CreatedAt, &v.UpdatedAt)

	if err != nil {
		log.Printf("Error creating vendor: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat vendor: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, v)
}

func updateVendor(c *gin.Context) {
	id := c.Param("id")
	var v Vendor
	if err := c.ShouldBindJSON(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	_, err := db.Exec(
		`UPDATE vendors SET company_name=$1, vendor_type=$2, updated_at=NOW()
		 WHERE id=$3`,
		v.CompanyName, v.VendorType, id,
	)
	if err != nil {
		log.Printf("Error updating vendor: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update vendor: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Vendor berhasil diupdate", "id": id})
}

func deleteVendor(c *gin.Context) {
	id := c.Param("id")

	_, err := db.Exec("DELETE FROM vendors WHERE id = $1", id)
	if err != nil {
		log.Printf("Error deleting vendor: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus vendor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Vendor berhasil dihapus"})
}
func getMaterials(c *gin.Context) {
    rows, err := db.Query(`
            SELECT id, material_code, material_description, location, 
                pack_quantity, max_bin_qty, min_bin_qty, 
                vendor_code, current_quantity, product_type
            FROM materials 
            ORDER BY material_code
        `)
    if err != nil {
        log.Printf("Error querying materials: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data material"})
        return
    }
    defer rows.Close()

    materials := make([]Material, 0)
    materialIDs := make([]int, 0) 
    materialMap := make(map[int]*Material)

    for rows.Next() {
        var m Material
        if err := rows.Scan(
            &m.ID,
            &m.MaterialCode,
            &m.MaterialDescription,
            &m.Location,
            &m.PackQuantity,
            &m.MaxBinQty,
            &m.MinBinQty,
            &m.VendorCode,
            &m.CurrentQuantity,
            &m.ProductType,
        ); err != nil {
            log.Printf("Error scanning material: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data material"})
            return
        }

        materials = append(materials, m)
        if m.ProductType != "kanban" {
            materialIDs = append(materialIDs, m.ID) 
            materialMap[m.ID] = &materials[len(materials)-1]
        }
    }
    if err := rows.Err(); err != nil {
        log.Printf("Error during material rows iteration: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Terjadi kesalahan saat memproses data material"})
        return
    }

    if len(materialIDs) > 0 {
        query := `
                SELECT id, material_id, bin_sequence_id, max_bin_stock, current_bin_stock
                FROM material_bins
                WHERE material_id = ANY($1)
                ORDER BY material_id, bin_sequence_id
            `

        binRows, err := db.Query(query, pq.Array(materialIDs))
        if err != nil {
            log.Printf("Error querying material bins: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data bin"})
            return
        }
        defer binRows.Close()

        for binRows.Next() {
            var b MaterialBin
            if err := binRows.Scan(
                &b.ID,
                &b.MaterialID,
                &b.BinSequenceID,
                &b.MaxBinStock,
                &b.CurrentBinStock,
            ); err != nil {
                log.Printf("Error scanning material bin: %v", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data bin"})
                return
            }

            if material, ok := materialMap[b.MaterialID]; ok {
                if material.Bins == nil {
                    material.Bins = make([]MaterialBin, 0)
                }
                material.Bins = append(material.Bins, b)
            }
        }
        if err := binRows.Err(); err != nil {
            log.Printf("Error during bin rows iteration: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Terjadi kesalahan saat memproses data bin"})
            return
        }
    }

    c.JSON(http.StatusOK, materials)
}
func createMaterial(c *gin.Context) {
	var m Material
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if m.PackQuantity <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity harus lebih besar dari 0"})
		return
	}
	if m.MaxBinQty < m.MinBinQty {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty tidak boleh lebih kecil dari Min Bin Qty"})
		return
	}

	if m.ProductType == "" {
		m.ProductType = "kanban"
	}

	if m.MaxBinQty > 0 && m.MaxBinQty%m.PackQuantity != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Max Bin Qty (%d) harus merupakan kelipatan dari Pack Quantity (%d)", m.MaxBinQty, m.PackQuantity)})
		return
	}

	// Validasi berdasarkan aturan baru
	if m.ProductType == "kanban" {
		// Validasi kelipatan sudah dipindah ke atas
		// (Sebelumnya ada cek 'm.MaxBinQty%m.PackQuantity != 0' di sini)
	} else {
		// Untuk Consumable/Option: bins harus disediakan
		if m.Bins == nil || len(m.Bins) == 0 {
			// Izinkan MaxBinQty 0 (0 bin)
			if m.MaxBinQty > 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "[Consumable/Option] Data bins dibutuhkan"})
				return
			}
		}

		if len(m.Bins) > 0 {
			qtyPerBin := m.Bins[0].MaxBinStock
			expectedMax := len(m.Bins) * qtyPerBin
			if m.MaxBinQty != expectedMax {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Inkonsistensi Max Qty: Dihitung %d (Bins: %d * Qty/Bin: %d) vs Input %d", expectedMax, len(m.Bins), qtyPerBin, m.MaxBinQty)})
				return
			}
			for _, bin := range m.Bins {
				if bin.MaxBinStock != qtyPerBin {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Inkonsistensi Qty/Bin: Semua bin harus memiliki maxBinStock yang sama"})
					return
				}
			}
		} else if m.MaxBinQty != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Inkonsistensi Data: Max Qty > 0 tetapi tidak ada data bin."})
			return
		}
	}

	m.CurrentQuantity = 0 

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
		return
	}
	defer tx.Rollback()

	err = tx.QueryRow(
		`INSERT INTO materials (
            material_code, material_description, location, 
            pack_quantity, max_bin_qty, min_bin_qty, 
            vendor_code, current_quantity, product_type
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id`,
		m.MaterialCode, m.MaterialDescription, m.Location,
		m.PackQuantity, m.MaxBinQty, m.MinBinQty,
		m.VendorCode, m.CurrentQuantity, m.ProductType,
	).Scan(&m.ID)

	if err != nil {
		log.Printf("Error creating material: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat material: " + err.Error()})
		return
	}

	if m.ProductType != "kanban" && len(m.Bins) > 0 {
		stmt, err := tx.Prepare(`
            INSERT INTO material_bins 
            (material_id, bin_sequence_id, max_bin_stock, current_bin_stock)
            VALUES ($1, $2, $3, $4)
            RETURNING id
        `)
		if err != nil {
			log.Printf("Error preparing bin statement: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan insert bin"})
			return
		}
		defer stmt.Close()

		for i, bin := range m.Bins {
			var binID int
			err := stmt.QueryRow(m.ID, bin.BinSequenceID, bin.MaxBinStock, 0).Scan(&binID) 
			if err != nil {
				log.Printf("Error inserting bin: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat bin material"})
				return
			}
			m.Bins[i].ID = binID
			m.Bins[i].MaterialID = m.ID
			m.Bins[i].CurrentBinStock = 0
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan material"})
		return
	}

	c.JSON(http.StatusCreated, m)
}
func updateMaterial(c *gin.Context) {
	id := c.Param("id")
	var m Material
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if m.ProductType == "" {
		m.ProductType = "kanban"
	}

	var oldQty int
	var oldProductType string
	err := db.QueryRow("SELECT current_quantity, product_type FROM materials WHERE id = $1", id).Scan(&oldQty, &oldProductType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Material tidak ditemukan"})
			return
		}
		log.Printf("Error querying old stock: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memverifikasi stok lama"})
		return
	}

	if m.CurrentQuantity != oldQty && m.PIC == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PIC (Nama Anda) wajib diisi saat mengubah Current Stock."})
		return
	}

	if m.CurrentQuantity != oldQty && m.PIC != "" {
		log.Printf("--- STOCK CHANGE: Material ID %s updated by %s (Old: %d, New: %d) ---", id, m.PIC, oldQty, m.CurrentQuantity)
	}

	if m.PackQuantity <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity harus lebih besar dari 0"})
		return
	}
	if m.MaxBinQty < m.MinBinQty {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty tidak boleh lebih kecil dari Min Bin Qty"})
		return
	}

	// --- PERBAIKAN ---
	// Validasi constraint database (check_pack_is_factor_of_max)
	// Ini harus berlaku untuk SEMUA tipe produk, bukan hanya 'kanban',
	// jadi dipindahkan ke luar blok 'if'.
	if m.MaxBinQty > 0 && m.MaxBinQty%m.PackQuantity != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Max Bin Qty (%d) harus merupakan kelipatan dari Pack Quantity (%d)", m.MaxBinQty, m.PackQuantity)})
		return
	}
	// -----------------

	// Validasi berdasarkan aturan baru
	if m.ProductType == "kanban" {
		// (Validasi kelipatan sudah dipindah ke atas)
		if m.CurrentQuantity > m.MaxBinQty {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Current Quantity (%d) tidak boleh melebihi Max Bin Qty (%d)", m.CurrentQuantity, m.MaxBinQty)})
			return
		}
		if m.CurrentQuantity < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Current Quantity tidak boleh negatif"})
			return
		}
	} else {
		// Untuk Consumable/Option: bins harus disediakan
		if m.Bins == nil {
			if m.MaxBinQty > 0 { // Izinkan 0 max qty
				c.JSON(http.StatusBadRequest, gin.H{"error": "[Consumable/Option] Data bins dibutuhkan"})
				return
			}
			// m.Bins == nil dan m.MaxBinQty == 0, set m.Bins jadi array kosong
			m.Bins = []MaterialBin{}
		}

		var calculatedTotalStock int = 0
		if len(m.Bins) > 0 {
			qtyPerBin := m.Bins[0].MaxBinStock
			expectedMax := len(m.Bins) * qtyPerBin
			if m.MaxBinQty != expectedMax {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Inkonsistensi Max Qty: Dihitung %d (Bins: %d * Qty/Bin: %d) vs Input %d", expectedMax, len(m.Bins), qtyPerBin, m.MaxBinQty)})
				return
			}

			for _, bin := range m.Bins {
				if bin.MaxBinStock != qtyPerBin {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Inkonsistensi Qty/Bin: Semua bin harus memiliki maxBinStock yang sama"})
					return
				}
				if bin.CurrentBinStock > bin.MaxBinStock {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Stok bin %d (%d) melebihi Qty/Bin (%d)", bin.BinSequenceID, bin.CurrentBinStock, bin.MaxBinStock)})
					return
				}
				if bin.CurrentBinStock < 0 {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Stok bin %d (%d) tidak boleh negatif", bin.BinSequenceID, bin.CurrentBinStock)})
					return
				}
				calculatedTotalStock += bin.CurrentBinStock
			}
		} else if m.MaxBinQty != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Inkonsistensi Data: Max Qty > 0 tetapi tidak ada data bin."})
			return
		}

		if m.CurrentQuantity != calculatedTotalStock {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Inkonsistensi Stok Total: Total %d vs Kalkulasi Bin %d", m.CurrentQuantity, calculatedTotalStock)})
			return
		}
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi update"})
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`UPDATE materials SET 
            material_code = $1, 
            material_description = $2, 
            location = $3, 
            pack_quantity = $4, 
            max_bin_qty = $5, 
            min_bin_qty = $6, 
            vendor_code = $7,
            current_quantity = $8,
            product_type = $9
        WHERE id = $10`,
		m.MaterialCode, m.MaterialDescription, m.Location,
		m.PackQuantity, m.MaxBinQty, m.MinBinQty,
		m.VendorCode, m.CurrentQuantity, m.ProductType,
		id,
	)

	if err != nil {
		log.Printf("Error updating material: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update material: " + err.Error()})
		return
	}

	// --- REBUILD BINS ---
	_, err = tx.Exec("DELETE FROM material_bins WHERE material_id = $1", id)
	if err != nil {
		log.Printf("Error deleting old bins: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus bin lama"})
		return
	}

	if m.ProductType != "kanban" && len(m.Bins) > 0 {
		stmt, err := tx.Prepare(`
            INSERT INTO material_bins 
            (material_id, bin_sequence_id, max_bin_stock, current_bin_stock)
            VALUES ($1, $2, $3, $4)
        `)
		if err != nil {
			log.Printf("Error preparing bin statement: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan insert bin"})
			return
		}
		defer stmt.Close()

		for _, bin := range m.Bins {
			// Gunakan bin data dari payload
			_, err := stmt.Exec(id, bin.BinSequenceID, bin.MaxBinStock, bin.CurrentBinStock)
			if err != nil {
				log.Printf("Error inserting bin: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat bin material"})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan update material"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Material berhasil diupdate", "id": id})
}

func deleteMaterial(c *gin.Context) {
	id := c.Param("id")

	var currentQty int
	err := db.QueryRow("SELECT current_quantity FROM materials WHERE id = $1", id).Scan(&currentQty)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Material tidak ditemukan"})
			return
		}
		log.Printf("Error checking material stock: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memverifikasi stok material"})
		return
	}

	if currentQty > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Gagal menghapus: Material masih memiliki stok (Current Quantity > 0). Harap kosongkan stok terlebih dahulu."})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi delete"})
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM material_bins WHERE material_id = $1", id)
	if err != nil {
		log.Printf("Error deleting material bins: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus bin material"})
		return
	}

	_, err = tx.Exec("DELETE FROM materials WHERE id = $1", id)
	if err != nil {
		log.Printf("Error deleting material: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus material"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus material"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Material berhasil dihapus (stok 0)"})
}

func scanAutoMaterials(c *gin.Context) {
	var scannedValues []string
	if err := c.ShouldBindJSON(&scannedValues); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if len(scannedValues) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tidak ada data scan untuk diproses"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
		return
	}
	defer tx.Rollback()

	for _, scannedValue := range scannedValues {

		parts := strings.Split(scannedValue, "_")
		var materialCode, binIDStr, movement, qtyStr string
		var scanFormat int // 1=Kanban, 2=Consumable/Option(IN/OUT), 3=Option(OUT QTY)

		if len(parts) == 2 {
			materialCode = parts[0]
			movement = strings.ToUpper(parts[1])
			scanFormat = 1 // [MaterialCode]_IN or [MaterialCode]_OUT
		} else if len(parts) == 3 {
			materialCode = parts[0]
			binIDStr = parts[1]
			movement = strings.ToUpper(parts[2])
			scanFormat = 2 // [MaterialCode]_[BinID]_IN or [MaterialCode]_[BinID]_OUT
		} else if len(parts) == 4 {
			materialCode = parts[0]
			binIDStr = parts[1]
			movement = strings.ToUpper(parts[2])
			qtyStr = parts[3]
			scanFormat = 3 // [MaterialCode]_[BinID]_OUT_[Qty]
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'", scannedValue)})
			return
		}

		if materialCode == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Material ID kosong dari scan: '%s'", scannedValue)})
			return
		}
		if movement != "IN" && movement != "OUT" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Movement scan salah: '%s' (perlu IN atau OUT)", movement)})
			return
		}

		var m Material
		err := tx.QueryRow(
			`SELECT id, pack_quantity, max_bin_qty, current_quantity, min_bin_qty, material_code, product_type
			 FROM materials 
			 WHERE material_code = $1 
			 FOR UPDATE`,
			materialCode,
		).Scan(&m.ID, &m.PackQuantity, &m.MaxBinQty, &m.CurrentQuantity, &m.MinBinQty, &m.MaterialCode, &m.ProductType)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Material tidak ditemukan: %s (dari scan '%s')", materialCode, scannedValue)})
				return
			}
			log.Printf("Error querying material %s: %v", materialCode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data material"})
			return
		}

		var newTotalQuantity int
		var binStockChange int = 0

		if scanFormat == 1 {
			if m.ProductType != "kanban" {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'. Material %s adalah tipe '%s', perlu scan per bin (e.g., %s_1_IN)", scannedValue, m.MaterialCode, m.ProductType, m.MaterialCode)})
				return
			}

			if movement == "IN" {
				newTotalQuantity = m.CurrentQuantity + m.PackQuantity
				if newTotalQuantity > m.MaxBinQty {
					c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s): Bin penuh (akan menjadi %d dari max %d)", m.MaterialCode, newTotalQuantity, m.MaxBinQty)})
					return
				}
				binStockChange = m.PackQuantity
			} else { // OUT
				newTotalQuantity = m.CurrentQuantity - m.PackQuantity
				if newTotalQuantity < 0 {
					c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s): Stok tidak mencukupi (akan menjadi %d)", m.MaterialCode, newTotalQuantity)})
					return
				}
				binStockChange = -m.PackQuantity
			}
		} else {
			if m.ProductType == "kanban" {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'. Material %s adalah tipe 'kanban', tidak perlu ID bin", scannedValue, m.MaterialCode)})
				return
			}

			binID, err := strconv.Atoi(binIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bin ID salah: '%s' (dari scan '%s')", binIDStr, scannedValue)})
				return
			}

			var currentBinStock int
			var maxBinStock int // = quantity per bin
			err = tx.QueryRow(
				`SELECT current_bin_stock, max_bin_stock FROM material_bins
				 WHERE material_id = $1 AND bin_sequence_id = $2
				 FOR UPDATE`,
				m.ID, binID,
			).Scan(&currentBinStock, &maxBinStock)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Bin %d untuk material %s tidak ditemukan", binID, m.MaterialCode)})
					return
				}
				log.Printf("Error querying bin stock %s-%d: %v", m.MaterialCode, binID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data stok bin"})
				return
			}

			if m.ProductType == "consumable" {
				if scanFormat == 3 {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'. Tipe 'consumable' tidak mendukung scan per PCS", scannedValue)})
					return
				}
				if movement == "IN" {
					if currentBinStock > 0 {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s Bin %d): Bin sudah terisi (stok %d)", m.MaterialCode, binID, currentBinStock)})
						return
					}
					binStockChange = maxBinStock // Isi penuh bin
					_, err = tx.Exec("UPDATE material_bins SET current_bin_stock = $1 WHERE material_id = $2 AND bin_sequence_id = $3", maxBinStock, m.ID, binID)
				} else { // OUT
					if currentBinStock == 0 {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s Bin %d): Bin sudah kosong", m.MaterialCode, binID)})
						return
					}
					binStockChange = -currentBinStock
					_, err = tx.Exec("UPDATE material_bins SET current_bin_stock = 0 WHERE material_id = $1 AND bin_sequence_id = $2", m.ID, binID)
				}
			} else if m.ProductType == "option" {
				if movement == "IN" {
					if scanFormat == 3 {
						c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'. Scan IN untuk tipe 'option' tidak perlu Qty", scannedValue)})
						return
					}
					if currentBinStock > 0 {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s Bin %d): Bin sudah terisi (stok %d)", m.MaterialCode, binID, currentBinStock)})
						return
					}
					binStockChange = maxBinStock // Isi penuh
					_, err = tx.Exec("UPDATE material_bins SET current_bin_stock = $1 WHERE material_id = $2 AND bin_sequence_id = $3", maxBinStock, m.ID, binID)
				} else { // OUT
					if scanFormat == 2 {
						c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'. Scan OUT tipe 'option' perlu Qty PCS (e.g., %s_1_OUT_10)", scannedValue, m.MaterialCode)})
						return
					}

					qty, _ := strconv.Atoi(qtyStr)
					if qty <= 0 {
						c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Qty scan salah: '%s' (harus > 0)", qtyStr)})
						return
					}

					if currentBinStock < qty {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s Bin %d): Stok tidak cukup (stok %d, butuh %d)", m.MaterialCode, binID, currentBinStock, qty)})
						return
					}

					newBinStock := currentBinStock - qty
					binStockChange = -qty
					_, err = tx.Exec("UPDATE material_bins SET current_bin_stock = $1 WHERE material_id = $2 AND bin_sequence_id = $3", newBinStock, m.ID, binID)
				}
			}

			if err != nil {
				log.Printf("Error updating bin stock %s-%d: %v", m.MaterialCode, binID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update stok bin"})
				return
			}
			newTotalQuantity = m.CurrentQuantity + binStockChange
		}

		_, err = tx.Exec(
			"UPDATE materials SET current_quantity = $1 WHERE id = $2",
			newTotalQuantity, m.ID,
		)
		if err != nil {
			log.Printf("Error updating total stock for %s: %v", m.MaterialCode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update total stok"})
			return
		}

		// Re-cek definisi reorder point
		reorderPoint := m.MinBinQty
		if m.ProductType == "kanban" {
			// Untuk Kanban, reorder point (merah) adalah MinQty, dan MinQty = PackQty
			// Tidak perlu perbandingan
		} else if m.ProductType == "consumable" {
			// Untuk Consumable, reorder point (merah) adalah MinQty, dan MinQty = PackQty
			// Tidak perlu perbandingan
		} else {
			// Untuk Option, reorder point (merah) adalah MinQty (input user, rounded)
			// Tidak perlu perbandingan
		}


		if movement == "OUT" && newTotalQuantity <= reorderPoint {
			log.Printf("--- TRIGGER VRO UNTUK: %s (Stok: %d, Titik Merah: %d) ---", m.MaterialCode, newTotalQuantity, reorderPoint)
		}

	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan transaksi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Semua transaksi manual berhasil disimpan"})
}

func getMaterialStatus(c *gin.Context) {
	materialCode := c.Query("code")
	if materialCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query 'code' dibutuhkan"})
		return
	}

	var m Material
	err := db.QueryRow(
		`SELECT pack_quantity, max_bin_qty, min_bin_qty, current_quantity, product_type
		 FROM materials 
		 WHERE material_code = $1`,
		materialCode,
	).Scan(&m.PackQuantity, &m.MaxBinQty, &m.MinBinQty, &m.CurrentQuantity, &m.ProductType)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Material tidak ditemukan: %s", materialCode)})
			return
		}
		log.Printf("Error querying material status %s: %v", materialCode, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data material"})
		return
	}

	var predictedMovement string
	if m.CurrentQuantity >= m.MaxBinQty {
		predictedMovement = "OUT"
	} else {
		predictedMovement = "IN"
	}

	response := MaterialStatusResponse{
		PackQuantity:      m.PackQuantity,
		MaxBinQty:         m.MaxBinQty,
		MinBinQty:         m.MinBinQty,
		CurrentQuantity:   m.CurrentQuantity,
		ProductType:       m.ProductType,
		PredictedMovement: predictedMovement,
	}

	c.JSON(http.StatusOK, response)
}