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
	VendorStock         int           `json:"vendorStock"`
	Bins                []MaterialBin `json:"bins,omitempty"`
}

type MaterialStatusResponse struct {
	PackQuantity      int           `json:"packQuantity"`
	MaxBinQty         int           `json:"maxBinQty"`
	MinBinQty         int           `json:"minBinQty"`
	CurrentQuantity   int           `json:"currentQuantity"`
	ProductType       string        `json:"productType"`
	PredictedMovement string        `json:"predictedMovement"`
	QuantityPerBin    int           `json:"quantityPerBin"`
	Bins              []MaterialBin `json:"bins,omitempty"`
	VendorStock       int           `json:"vendorStock"`
}

type MaterialBin struct {
	ID              int `json:"id"`
	MaterialID      int `json:"materialId"`
	BinSequenceID   int `json:"binSequenceId"`
	MaxBinStock     int `json:"maxBinStock"`
	CurrentBinStock int `json:"currentBinStock"`
}

type StockMovement struct {
	ID             int       `json:"id"`
	MaterialID     int       `json:"materialId"`
	MaterialCode   string    `json:"materialCode"`
	MovementType   string    `json:"movementType"`
	QuantityChange int       `json:"quantityChange"`
	OldQuantity    int       `json:"oldQuantity"`
	NewQuantity    int       `json:"newQuantity"`
	PIC            string    `json:"pic"`
	Notes          sql.NullString `json:"notes"`
	BinSequenceID  sql.NullInt64  `json:"binSequenceId,omitempty"` 
	Timestamp      time.Time `json:"timestamp"`
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
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-User-Role", "X-User-Company"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(config))
	api := router.Group("/api")
	api.Use(AuthMiddleware())

	{
		api.POST("/login", loginUser)

		users := api.Group("/users")
		{
			users.GET("/", AdminOrSuperuserAuthMiddleware(), getUsers)
			users.POST("/", SuperuserOnlyAuthMiddleware(), createUser)
			users.PUT("/:id", SuperuserOnlyAuthMiddleware(), updateUser)
			users.DELETE("/:id", SuperuserOnlyAuthMiddleware(), deleteUser)
		}

		api.GET("/vendor-type", getVendorTypes)
		api.GET("/companies", getCompanies)

		vendors := api.Group("/vendors")
		{
			vendors.GET("/", AdminOrSuperuserAuthMiddleware(), getVendors)
			vendors.POST("/", SuperuserOnlyAuthMiddleware(), createVendor)
			vendors.PUT("/:id", SuperuserOnlyAuthMiddleware(), updateVendor)
			vendors.DELETE("/:id", SuperuserOnlyAuthMiddleware(), deleteVendor)
		}

		materials := api.Group("/materials")
		{
			materials.GET("/", getMaterials)
			materials.GET("/status", getMaterialStatus)
			materials.POST("/scan/auto", ScanAuthMiddleware(), scanAutoMaterials)

			materials.POST("/", SuperuserOnlyAuthMiddleware(), createMaterial)
			materials.PUT("/:id", MaterialEditAuthMiddleware(), updateMaterial)
			materials.GET("/:id/movements", getStockMovements)
			materials.DELETE("/:id", SuperuserOnlyAuthMiddleware(), deleteMaterial)
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
		if c.Request.URL.Path == "/api/login" {
			c.Next()
			return
		}

		role := c.GetHeader("X-User-Role")
		if role == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Header X-User-Role dibutuhkan"})
			return
		}
		validRoles := map[string]bool{
			"Superuser": true,
			"Admin":     true,
			"Vendor":    true,
			"Viewer":    true,
		}
		if !validRoles[role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Role tidak valid: " + role})
			return
		}

		c.Next()
	}
}

func SuperuserOnlyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetHeader("X-User-Role")
		if role != "Superuser" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Hanya Superuser yang diizinkan"})
			return
		}
		c.Next()
	}
}

func AdminOrSuperuserAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetHeader("X-User-Role")
		if role != "Admin" && role != "Superuser" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Hanya Admin atau Superuser yang diizinkan"})
			return
		}
		c.Next()
	}
}

func ScanAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetHeader("X-User-Role")
		if role == "Viewer" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Viewer tidak diizinkan melakukan scan"})
			return
		}
		if role != "Superuser" && role != "Admin" && role != "Vendor" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
			return
		}
		c.Next()
	}
}

func MaterialEditAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetHeader("X-User-Role")
		if role != "Superuser" && role != "Admin" && role != "Vendor" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Hanya Superuser, Admin, atau Vendor yang diizinkan"})
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

	if req.Role == "Vendor" && (!req.CompanyName.Valid || req.CompanyName.String == "") {
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

	if req.Role == "Vendor" && (!req.CompanyName.Valid || req.CompanyName.String == "") {
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
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")

	baseQuery := `
        SELECT id, material_code, material_description, location, 
            pack_quantity, max_bin_qty, min_bin_qty, 
            vendor_code, current_quantity, product_type,
            vendor_stock
        FROM materials
    `
	var queryParams []interface{}

	if role == "Vendor" {
		if companyName == "" {
			log.Println("Peringatan: Role Vendor memanggil getMaterials tanpa X-User-Company")
			c.JSON(http.StatusForbidden, gin.H{"error": "Akses vendor ditolak: company name tidak ada"})
			return
		}
		baseQuery += " WHERE vendor_code = $1 ORDER BY material_code"
		queryParams = append(queryParams, companyName)
	} else {
		baseQuery += " ORDER BY material_code"
	}

	rows, err := db.Query(baseQuery, queryParams...)
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
			&m.VendorStock,
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

	if m.ProductType == "" {
		m.ProductType = "kanban"
	}

	if m.ProductType == "option" {
		m.PackQuantity = 1
		m.MinBinQty = 1
	}

	if m.PackQuantity <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity harus lebih besar dari 0"})
		return
	}
	if m.MaxBinQty < m.MinBinQty {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty tidak boleh lebih kecil dari Min Bin Qty"})
		return
	}
	if m.VendorStock < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Vendor Stock tidak boleh negatif"})
		return
	}

	if m.MaxBinQty > 0 && m.MaxBinQty%m.PackQuantity != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Max Bin Qty (%d) harus merupakan kelipatan dari Pack Quantity (%d)", m.MaxBinQty, m.PackQuantity)})
		return
	}

	if m.ProductType == "kanban" {
	} else {
		if m.Bins == nil || len(m.Bins) == 0 {
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
            vendor_code, current_quantity, product_type,
            vendor_stock
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id`,
		m.MaterialCode, m.MaterialDescription, m.Location,
		m.PackQuantity, m.MaxBinQty, m.MinBinQty,
		m.VendorCode, m.CurrentQuantity, m.ProductType,
		m.VendorStock,
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
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")

	var m Material
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if m.ProductType == "" {
		m.ProductType = "kanban"
	}

	if m.ProductType == "option" {
		m.PackQuantity = 1
		m.MinBinQty = 1
	}

	var oldQty int
	var oldProductType string
	var oldVendorCode string

	err := db.QueryRow("SELECT current_quantity, product_type, vendor_code, material_code FROM materials WHERE id = $1", id).Scan(&oldQty, &oldProductType, &oldVendorCode, &m.MaterialCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Material tidak ditemukan"})
			return
		}
		log.Printf("Error querying old stock: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memverifikasi stok lama"})
		return
	}

	if role == "Vendor" {
		if companyName == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Identitas perusahaan tidak ditemukan"})
			return
		}
		if oldVendorCode != companyName {
			c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda tidak dapat mengedit material vendor lain"})
			return
		}
		m.VendorCode = companyName
	}

	if m.CurrentQuantity != oldQty && m.PIC == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PIC (Nama Anda) wajib diisi saat mengubah Current Stock."})
		return
	}

	if m.CurrentQuantity != oldQty && m.PIC != "" {
		log.Printf("--- STOCK CHANGE: Material ID %s updated by %s (Old: %d, New: %d) ---", id, m.PIC, oldQty, m.CurrentQuantity)
	}

	// (Validasi sisa...)
	if m.PackQuantity <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity harus lebih besar dari 0"})
		return
	}
	if m.MaxBinQty < m.MinBinQty {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty tidak boleh lebih kecil dari Min Bin Qty"})
		return
	}
	if m.VendorStock < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Vendor Stock tidak boleh negatif"})
		return
	}
	if m.MaxBinQty > 0 && m.MaxBinQty%m.PackQuantity != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Max Bin Qty (%d) harus merupakan kelipatan dari Pack Quantity (%d)", m.MaxBinQty, m.PackQuantity)})
		return
	}
	if m.ProductType == "kanban" {
		if m.CurrentQuantity > m.MaxBinQty {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Current Quantity (%d) tidak boleh melebihi Max Bin Qty (%d)", m.CurrentQuantity, m.MaxBinQty)})
			return
		}
		if m.CurrentQuantity < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Current Quantity tidak boleh negatif"})
			return
		}
	} else {
		if m.Bins == nil {
			if m.MaxBinQty > 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "[Consumable/Option] Data bins dibutuhkan"})
				return
			}
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

	if m.CurrentQuantity != oldQty {
		change := m.CurrentQuantity - oldQty
		// **[DIUBAH] Menambahkan bin_sequence_id = NULL**
		_, errLog := tx.Exec(
			`INSERT INTO stock_movements 
			 (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
			 VALUES ($1, $2, 'Edit', $3, $4, $5, $6, 'Manual Stock Edit', NULL)`, // <-- Tambah NULL
			id, m.MaterialCode, change, oldQty, m.CurrentQuantity, m.PIC,
		)
		if errLog != nil {
			log.Printf("Error logging stock movement: %v", errLog)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mencatat histori stok"})
			return
		}
	}

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
			product_type = $9,
			vendor_stock = $10
		WHERE id = $11`,
		m.MaterialCode, m.MaterialDescription, m.Location,
		m.PackQuantity, m.MaxBinQty, m.MinBinQty,
		m.VendorCode, m.CurrentQuantity, m.ProductType,
		m.VendorStock,
		id,
	)

	if err != nil {
		log.Printf("Error updating material: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update material: " + err.Error()})
		return
	}

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
func scanAutoMaterials(c *gin.Context) {
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")

	pic := role
	if role != "Superuser" && companyName != "" {
		pic = fmt.Sprintf("%s (%s)", role, companyName)
	}

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
		var materialCode, movement, binIDStr, qtyStr string
		var binID, qtyInput int
		var hasExplicitQty bool

		if len(parts) == 3 {
			materialCode = parts[0]
			movement = strings.ToUpper(parts[1])
			binIDStr = parts[2]
			qtyInput = 1
			hasExplicitQty = false
		} else if len(parts) == 4 {
			materialCode = parts[0]
			movement = strings.ToUpper(parts[1])
			binIDStr = parts[2]
			qtyStr = parts[3]
			hasExplicitQty = true

			var err error
			qtyInput, err = strconv.Atoi(qtyStr)
			if err != nil || qtyInput <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Qty salah: '%s' (dari scan '%s')", qtyStr, scannedValue)})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s' (perlu 3 or 4 bagian)", scannedValue)})
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

		binID, err := strconv.Atoi(binIDStr) 
		if err != nil || binID <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bin ID salah: '%s' (dari scan '%s')", binIDStr, scannedValue)})
			return
		}

		var m Material
		err = tx.QueryRow(
			`SELECT id, pack_quantity, max_bin_qty, current_quantity, min_bin_qty, material_code, product_type,
			 vendor_stock, vendor_code
			 FROM materials 
			 WHERE material_code = $1 
			 FOR UPDATE`,
			materialCode,
		).Scan(
			&m.ID, &m.PackQuantity, &m.MaxBinQty, &m.CurrentQuantity, &m.MinBinQty,
			&m.MaterialCode, &m.ProductType,
			&m.VendorStock, &m.VendorCode,
		)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Material tidak ditemukan: %s (dari scan '%s')", materialCode, scannedValue)})
				return
			}
			log.Printf("Error querying material %s: %v", materialCode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data material"})
			return
		}

		if role == "Vendor" {
			if companyName == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses vendor ditolak: company name tidak ada"})
				return
			}
			if m.VendorCode != companyName {
				c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Akses ditolak: Vendor %s tidak diizinkan scan material %s (Vendor: %s)", companyName, m.MaterialCode, m.VendorCode)})
				return
			}
		}

		var binStockChangeInPcs int = 0
		var newVendorStock int = m.VendorStock

		if movement == "IN" {
			if hasExplicitQty {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format IN salah: '%s'. Tidak perlu Qty (cth: %s_IN_%d)", scannedValue, m.MaterialCode, binID)})
				return
			}
			var currentBinStock int
			var maxBinStock int
			if m.ProductType == "kanban" {
				maxBinStock = m.PackQuantity
				currentBinStock = -1
			} else {
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
			}
			if currentBinStock > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s Bin %d): Bin sudah terisi (stok %d)", m.MaterialCode, binID, currentBinStock)})
				return
			}
			binStockChangeInPcs = maxBinStock
			if m.VendorStock < binStockChangeInPcs {
				c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s): Vendor Stock tidak cukup (Stok: %d, Butuh: %d)", m.MaterialCode, m.VendorStock, binStockChangeInPcs)})
				return
			}
			if m.CurrentQuantity+binStockChangeInPcs > m.MaxBinQty {
				c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s): Stok total akan melebihi Max (%d / %d)", m.MaterialCode, m.CurrentQuantity+binStockChangeInPcs, m.MaxBinQty)})
				return
			}
			newVendorStock = m.VendorStock - binStockChangeInPcs
			if m.ProductType != "kanban" {
				_, err = tx.Exec("UPDATE material_bins SET current_bin_stock = $1 WHERE material_id = $2 AND bin_sequence_id = $3", maxBinStock, m.ID, binID)
				if err != nil {
					log.Printf("Error updating bin stock %s-%d: %v", m.MaterialCode, binID, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update stok bin"})
					return
				}
			}
		} else {
			if m.ProductType == "kanban" {
				if hasExplicitQty {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format OUT salah: '%s'. Kanban tidak perlu Qty (cth: %s_OUT_%d)", scannedValue, m.MaterialCode, binID)})
					return
				}
				binStockChangeInPcs = -m.PackQuantity
				if m.CurrentQuantity+binStockChangeInPcs < 0 {
					c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s): Stok tidak mencukupi (akan menjadi %d)", m.MaterialCode, m.CurrentQuantity+binStockChangeInPcs)})
					return
				}
			} else {
				var currentBinStock int
				var maxBinStock int
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
				if currentBinStock == 0 {
					c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s Bin %d): Bin sudah kosong", m.MaterialCode, binID)})
					return
				}
				binStockChangeInPcs = -(qtyInput * m.PackQuantity)
				if currentBinStock+binStockChangeInPcs < 0 {
					c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s Bin %d): Stok bin tidak cukup (stok %d, butuh %d)", m.MaterialCode, binID, currentBinStock, -binStockChangeInPcs)})
					return
				}
				newBinStock := currentBinStock + binStockChangeInPcs
				_, err = tx.Exec("UPDATE material_bins SET current_bin_stock = $1 WHERE material_id = $2 AND bin_sequence_id = $3", newBinStock, m.ID, binID)
				if err != nil {
					log.Printf("Error updating bin stock %s-%d: %v", m.MaterialCode, binID, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update stok bin"})
					return
				}
			}
		}

		oldTotalQuantity := m.CurrentQuantity
		newTotalQuantity := oldTotalQuantity + binStockChangeInPcs

		_, err = tx.Exec(
			"UPDATE materials SET current_quantity = $1, vendor_stock = $2 WHERE id = $3",
			newTotalQuantity,
			newVendorStock,
			m.ID,
		)

		if err != nil {
			log.Printf("Error updating total stock for %s: %v", m.MaterialCode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update total stok"})
			return
		}

		var movementType string
		if movement == "IN" {
			movementType = "Scan IN"
		} else {
			movementType = "Scan OUT"
		}

		notes := fmt.Sprintf("Scan Bin %d", binID)
		if hasExplicitQty && movement == "OUT" {
			notes = fmt.Sprintf("Scan OUT Bin %d (Qty: %d)", binID, qtyInput)
		}

		_, errLog := tx.Exec(
			`INSERT INTO stock_movements 
			 (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			m.ID, m.MaterialCode, movementType, binStockChangeInPcs, oldTotalQuantity, newTotalQuantity, pic, notes, binID, // <-- Tambah binID
		)

		if errLog != nil {
			log.Printf("Error logging stock movement: %v", errLog)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mencatat histori stok scan"})
			return
		}

		if movement == "OUT" && newTotalQuantity <= m.MinBinQty {
			log.Printf("--- TRIGGER VRO UNTUK: %s (Stok: %d, Titik Merah: %d) ---", m.MaterialCode, newTotalQuantity, m.MinBinQty)
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
	var quantityPerBin int
	var bins []MaterialBin

	err := db.QueryRow(
		`SELECT id, pack_quantity, max_bin_qty, min_bin_qty, current_quantity, product_type,
         vendor_stock
         FROM materials 
         WHERE material_code = $1`,
		materialCode,
	).Scan(
		&m.ID, &m.PackQuantity, &m.MaxBinQty, &m.MinBinQty,
		&m.CurrentQuantity, &m.ProductType,
		&m.VendorStock,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Material tidak ditemukan: %s", materialCode)})
			return
		}
		log.Printf("Error querying material status %s: %v", materialCode, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data material"})
		return
	}

	bins = make([]MaterialBin, 0)

	if m.ProductType == "kanban" {
		quantityPerBin = m.PackQuantity
	} else {
		binRows, err := db.Query(
			`SELECT id, material_id, bin_sequence_id, max_bin_stock, current_bin_stock
             FROM material_bins WHERE material_id = $1 ORDER BY bin_sequence_id`,
			m.ID,
		)
		if err != nil {
			log.Printf("Error querying bins for %s: %v", materialCode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data bin material"})
			return
		}
		defer binRows.Close()

		for binRows.Next() {
			var b MaterialBin
			if err := binRows.Scan(&b.ID, &b.MaterialID, &b.BinSequenceID, &b.MaxBinStock, &b.CurrentBinStock); err != nil {
				log.Printf("Error scanning bin for %s: %v", materialCode, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai bin"})
				return
			}
			bins = append(bins, b)
		}

		if len(bins) > 0 {
			quantityPerBin = bins[0].MaxBinStock
		} else {
			quantityPerBin = m.PackQuantity
			log.Printf("Warning: Material non-kanban %s tidak memiliki data bin. Fallback Qty/Bin ke PackQty.", materialCode)
		}
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
		QuantityPerBin:    quantityPerBin,
		Bins:              bins,
		VendorStock:       m.VendorStock,
	}

	c.JSON(http.StatusOK, response)
}

func getStockMovements(c *gin.Context) {
	materialID := c.Param("id")

	var materialCode string
	err := db.QueryRow("SELECT material_code FROM materials WHERE id = $1", materialID).Scan(&materialCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Material tidak ditemukan"})
			return
		}
		log.Printf("Error checking material: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memverifikasi material"})
		return
	}

	rows, err := db.Query(
		`SELECT id, material_id, material_code, movement_type, 
				quantity_change, old_quantity, new_quantity, pic, notes, timestamp, bin_sequence_id
		 FROM stock_movements 
		 WHERE material_id = $1 
		 ORDER BY timestamp DESC`,
		materialID,
	)
	if err != nil {
		log.Printf("Error querying stock movements: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil histori stok"})
		return
	}
	defer rows.Close()

	movements := make([]StockMovement, 0)
	for rows.Next() {
		var m StockMovement
		if err := rows.Scan(
			&m.ID, &m.MaterialID, &m.MaterialCode, &m.MovementType,
			&m.QuantityChange, &m.OldQuantity, &m.NewQuantity, &m.PIC, &m.Notes, &m.Timestamp, &m.BinSequenceID,
		); err != nil {
			log.Printf("Error scanning stock movement: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai histori stok"})
			return
		}
		movements = append(movements, m)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error during movement rows iteration: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Terjadi kesalahan saat memproses data histori"})
		return
	}

	c.JSON(http.StatusOK, movements)
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