package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
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

type VendorStockUpdateRequest struct {
	MaterialCode string `json:"materialCode"`
	VendorStock  int    `json:"vendorStock"`
	OpenPO       int    `json:"openPO"`
}

type Material struct {
	ID                  int            `json:"id"`
	MaterialCode        string         `json:"material" binding:"required"`
	MaterialDescription string         `json:"materialDescription"`
	Location            string         `json:"lokasi"`
	PackQuantity        int            `json:"packQuantity" binding:"required"`
	MaxBinQty           int            `json:"maxBinQty" binding:"required"`
	MinBinQty           int            `json:"minBinQty" binding:"required"`
	VendorCode          string         `json:"vendorCode"`
	CurrentQuantity     int            `json:"currentQuantity"`
	PIC                 string         `json:"pic"`
	ProductType         string         `json:"productType"`
	PreviousProductType sql.NullString `json:"previousProductType"`
	VendorStock         int            `json:"vendorStock"`
	OpenPO              int            `json:"openPO"`
	Bins                []MaterialBin  `json:"bins,omitempty"`
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
	OpenPO            int           `json:"openPO"`
}

type MaterialBin struct {
	ID              int `json:"id"`
	MaterialID      int `json:"materialId"`
	BinSequenceID   int `json:"binSequenceId"`
	MaxBinStock     int `json:"maxBinStock"`
	CurrentBinStock int `json:"currentBinStock"`
}

type StockMovement struct {
	ID             int            `json:"id"`
	MaterialID     int            `json:"materialId"`
	MaterialCode   string         `json:"materialCode"`
	MovementType   string         `json:"movementType"`
	QuantityChange int            `json:"quantityChange"`
	OldQuantity    int            `json:"oldQuantity"`
	NewQuantity    int            `json:"newQuantity"`
	PIC            string         `json:"pic"`
	Notes          sql.NullString `json:"notes"`
	BinSequenceID  sql.NullInt64  `json:"binSequenceId,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

type DownloadLogRequest struct {
	Username string `json:"username" binding:"required"`
}

type DownloadLog struct {
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
}

type SmartMaterialRequest struct {
	MaterialCode        string        `json:"material" binding:"required"`
	MaterialDescription *string       `json:"materialDescription"`
	Location            *string       `json:"lokasi"`
	PackQuantity        *int          `json:"packQuantity"`
	MaxBinQty           *int          `json:"maxBinQty"`
	MinBinQty           *int          `json:"minBinQty"`
	VendorCode          *string       `json:"vendorCode"`
	CurrentQuantity     *int          `json:"currentQuantity"`
	ProductType         string        `json:"productType"`
	Bins                []MaterialBin `json:"bins,omitempty"`
}

var db *sql.DB

func main() {

	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found — assuming production environment")
	}
	connStr := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
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
		AllowOrigins:     []string{"https://vro-fe.vercel.app", "http://localhost:3000", "http://localhost:3001", "http://72.61.210.181:3001", "http://72.61.210.181:3000", "http://72.61.210.181"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-User-Role", "X-User-Company", "X-User-Username"},
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
		api.GET("/movements", getAllStockMovements)
		materials := api.Group("/materials")
		{
			materials.GET("/", getMaterials)
			materials.GET("/status", getMaterialStatus)
			materials.POST("/scan/auto", ScanAuthMiddleware(), scanAutoMaterials)
			materials.POST("/smart-import", SuperuserOnlyAuthMiddleware(), smartImportMaterial)
			materials.POST("/bulk-stock", MaterialEditAuthMiddleware(), bulkUpdateVendorStock)

			materials.POST("/", SuperuserOnlyAuthMiddleware(), createMaterial)
			materials.PUT("/:id", MaterialEditAuthMiddleware(), updateMaterial)
			materials.GET("/:id/movements", getStockMovements)
			materials.DELETE("/:id", SuperuserOnlyAuthMiddleware(), deleteMaterial)
			materials.PATCH("/:id/block", MaterialEditAuthMiddleware(), blockMaterial)
			materials.PATCH("/:id/unblock", MaterialEditAuthMiddleware(), unblockMaterial)

		}

		logs := api.Group("/logs")
		{
			logs.POST("/download", recordDownload)
			logs.GET("/last-download", getLastDownload)
		}
	}
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "API running"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8092"
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
func bulkUpdateVendorStock(c *gin.Context) {
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")
	username := c.GetHeader("X-User-Username")

	pic := username
	if pic == "" {
		pic = role
	}

	var requests []VendorStockUpdateRequest
	if err := c.ShouldBindJSON(&requests); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
		return
	}

	if len(requests) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Data kosong"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi: " + err.Error()})
		return
	}
	defer tx.Rollback()

	updatedCount := 0
	errorsList := []string{}

	for _, req := range requests {

		var id int
		var oldVendorStock int
		var currentVendorCode string

		errScan := tx.QueryRow(`
            SELECT id, vendor_stock, vendor_code 
            FROM materials 
            WHERE material_code = $1 
            FOR UPDATE`,
			req.MaterialCode,
		).Scan(&id, &oldVendorStock, &currentVendorCode)

		if errScan != nil {
			if errScan == sql.ErrNoRows {
				errorsList = append(errorsList, fmt.Sprintf("❌ %s: Material tidak ditemukan", req.MaterialCode))
			} else {
				errorsList = append(errorsList, fmt.Sprintf("❌ %s: DB Error saat cek data", req.MaterialCode))
			}
			continue
		}

		if role == "Vendor" && currentVendorCode != companyName {
			errorsList = append(errorsList, fmt.Sprintf("⛔ %s: Hak akses ditolak (Milik %s)", req.MaterialCode, currentVendorCode))
			continue
		}

		_, errUpdate := tx.Exec(`
            UPDATE materials 
            SET vendor_stock = $1, open_po = $2
            WHERE id = $3`,
			req.VendorStock, req.OpenPO, id,
		)

		if errUpdate != nil {
			log.Printf("SQL Error update %s: %v", req.MaterialCode, errUpdate)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error saat update " + req.MaterialCode})
			return
		}

		diff := req.VendorStock - oldVendorStock

		if diff != 0 {
			_, errLog := tx.Exec(`
                INSERT INTO stock_movements 
                (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
                VALUES ($1, $2, 'Edit Vendor', $3, $4, $5, $6, 'Edit Vendor Stock', NULL)`,
				id,
				req.MaterialCode,
				diff,
				oldVendorStock,
				req.VendorStock,
				pic,
			)

			if errLog != nil {
				log.Printf("Gagal log history untuk %s: %v", req.MaterialCode, errLog)
			}
		}

		updatedCount++
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Commit Failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit transaksi: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Proses selesai",
		"updatedCount": updatedCount,
		"errors":       errorsList,
	})
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

func getAllStockMovements(c *gin.Context) {
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")

	// Base query: Join dengan materials untuk cek akses vendor
	query := `
        SELECT 
            sm.id, sm.material_id, sm.material_code, sm.movement_type, 
            sm.quantity_change, sm.old_quantity, sm.new_quantity, 
            sm.pic, sm.notes, sm.timestamp, sm.bin_sequence_id
        FROM stock_movements sm
        JOIN materials m ON sm.material_id = m.id
    `

	var params []any

	// Filter khusus Vendor
	if role == "Vendor" {
		if companyName == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Vendor tanpa company tidak boleh akses"})
			return
		}
		query += " WHERE m.vendor_code = $1"
		params = append(params, companyName)
	}

	// Urutkan dari yang terbaru
	query += " ORDER BY sm.timestamp DESC"

	rows, err := db.Query(query, params...)
	if err != nil {
		log.Printf("Error querying all movements: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data histori"})
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
			log.Printf("Error scanning movement: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data histori"})
			return
		}
		movements = append(movements, m)
	}

	c.JSON(http.StatusOK, movements)
}

func getMaterials(c *gin.Context) {
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")

	query := `
        SELECT id, material_code, material_description, location,
               pack_quantity, max_bin_qty, min_bin_qty,
               vendor_code, current_quantity, product_type,
               vendor_stock, open_po
        FROM materials
    `

	var params []any

	if role == "Vendor" {
		if companyName == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Vendor tanpa company tidak boleh akses"})
			return
		}
		query += " WHERE vendor_code = $1 ORDER BY material_code"
		params = append(params, companyName)
	} else {
		query += " ORDER BY material_code"
	}

	rows, err := db.Query(query, params...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal query materials"})
		return
	}
	defer rows.Close()

	materials := []Material{}
	materialIDs := []int{}
	materialMap := map[int]int{}

	for rows.Next() {
		var m Material
		if err := rows.Scan(
			&m.ID, &m.MaterialCode, &m.MaterialDescription, &m.Location,
			&m.PackQuantity, &m.MaxBinQty, &m.MinBinQty,
			&m.VendorCode, &m.CurrentQuantity, &m.ProductType,
			&m.VendorStock, &m.OpenPO,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal scan material"})
			return
		}

		materials = append(materials, m)
		materialMap[m.ID] = len(materials) - 1
		materialIDs = append(materialIDs, m.ID)
	}

	if len(materialIDs) > 0 {
		binRows, err := db.Query(`
            SELECT id, material_id, bin_sequence_id, max_bin_stock, current_bin_stock
            FROM material_bins
            WHERE material_id = ANY($1)
            ORDER BY material_id, bin_sequence_id
        `, pq.Array(materialIDs))

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal ambil bins"})
			return
		}
		defer binRows.Close()

		for binRows.Next() {
			var b MaterialBin
			if err := binRows.Scan(
				&b.ID, &b.MaterialID, &b.BinSequenceID,
				&b.MaxBinStock, &b.CurrentBinStock,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal scan bin"})
				return
			}

			idx := materialMap[b.MaterialID]
			materials[idx].Bins = append(materials[idx].Bins, b)
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

	// Logic untuk "special" (Special Consumable)
	if m.ProductType == "special" {
		// Validasi khusus untuk special consumable
		if m.PackQuantity <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity wajib diisi > 0 untuk tipe Special Consumable"})
			return
		}
		// Abaikan MaxBinQty/MinBinQty validasi ketat, atau set default jika perlu
		if m.MaxBinQty <= 0 {
			m.MaxBinQty = m.PackQuantity // Set minimal sama agar lolos constraint DB
		}
		// Paksa tidak ada bin
		m.Bins = []MaterialBin{}
	}

	if m.ProductType == "option" {
		if m.PackQuantity == 0 {
			m.PackQuantity = 1
		}
		if m.MinBinQty == 0 {
			m.MinBinQty = 1
		}
	}

	// Validasi umum (jika bukan special yang sudah dihandle di atas)
	if m.ProductType != "special" {
		if m.MaxBinQty > 0 && m.MinBinQty > 0 && m.MaxBinQty < m.MinBinQty {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty tidak boleh lebih kecil dari Min Bin Qty"})
			return
		}

		if m.ProductType == "kanban" && m.PackQuantity > 0 && m.MaxBinQty > 0 {
			if m.MaxBinQty%m.PackQuantity != 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty harus kelipatan Pack Quantity"})
				return
			}
		}

		if m.MaxBinQty > 0 && m.CurrentQuantity > m.MaxBinQty {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Current Quantity (%d) tidak boleh melebihi Max Bin Qty (%d)", m.CurrentQuantity, m.MaxBinQty)})
			return
		}
	}

	// Generate Bins
	if m.ProductType == "kanban" {
		if m.PackQuantity > 0 && m.MaxBinQty > 0 {
			totalBins := m.MaxBinQty / m.PackQuantity
			m.Bins = make([]MaterialBin, totalBins)

			for i := 1; i <= totalBins; i++ {
				m.Bins[i-1] = MaterialBin{
					BinSequenceID:   i,
					MaxBinStock:     m.PackQuantity,
					CurrentBinStock: 0,
				}
			}
		} else {
			m.Bins = []MaterialBin{}
		}
	} else if m.ProductType == "special" {
		// Pastikan benar-benar kosong
		m.Bins = []MaterialBin{}
	} else {
		// Option atau lainnya
		if m.Bins == nil {
			m.Bins = []MaterialBin{}
		}
	}

	// Isi stok awal ke bin (Hanya jika bukan special dan punya bin)
	if m.ProductType != "special" && m.CurrentQuantity > 0 && len(m.Bins) > 0 {
		remainingStock := m.CurrentQuantity

		for i := range m.Bins {
			if remainingStock <= 0 {
				break
			}

			space := m.Bins[i].MaxBinStock

			if space <= 0 {
				continue
			}

			fillAmount := 0
			if remainingStock >= space {
				fillAmount = space
			} else {
				fillAmount = remainingStock
			}

			m.Bins[i].CurrentBinStock = fillAmount
			remainingStock -= fillAmount
		}
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
		return
	}
	defer tx.Rollback()

	err = tx.QueryRow(`
        INSERT INTO materials (
            material_code, material_description, location,
            pack_quantity, max_bin_qty, min_bin_qty,
            vendor_code, current_quantity, product_type,
            vendor_stock, open_po
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        RETURNING id`,
		m.MaterialCode, m.MaterialDescription, m.Location,
		m.PackQuantity, m.MaxBinQty, m.MinBinQty,
		m.VendorCode, m.CurrentQuantity, m.ProductType,
		m.VendorStock, m.OpenPO,
	).Scan(&m.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat material: " + err.Error()})
		return
	}

	if m.CurrentQuantity > 0 {
		_, errLog := tx.Exec(`
            INSERT INTO stock_movements 
            (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
            VALUES ($1, $2, 'Initial Stock', $3, 0, $3, 'System', 'Manual Create', NULL)`,
			m.ID, m.MaterialCode, m.CurrentQuantity,
		)
		if errLog != nil {
			log.Printf("Gagal log initial stock: %v", errLog)

		}
	}

	// Insert Bins jika ada
	if len(m.Bins) > 0 {
		stmt, err := tx.Prepare(`
            INSERT INTO material_bins (material_id, bin_sequence_id, max_bin_stock, current_bin_stock)
            VALUES ($1,$2,$3,$4)
        `)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan insert bins"})
			return
		}
		defer stmt.Close()

		for _, bin := range m.Bins {
			_, err := stmt.Exec(m.ID, bin.BinSequenceID, bin.MaxBinStock, bin.CurrentBinStock)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal insert bins: " + err.Error()})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit material"})
		return
	}

	c.JSON(http.StatusCreated, m)
}
func scanAutoMaterials(c *gin.Context) {
	role := c.GetHeader("X-User-Role")
	companyName := c.GetHeader("X-User-Company")
	username := c.GetHeader("X-User-Username")

	pic := username
	if pic == "" {
		pic = role
	}

	var scannedValues []string
	if err := c.ShouldBindJSON(&scannedValues); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Format payload salah"})
		return
	}
	if len(scannedValues) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tidak ada data scan"})
		return
	}

	type ScanItem struct {
		Raw      string
		Material string
		Movement string
		BinID    int
		Qty      int
	}

	groupedScans := make(map[string][]ScanItem)

	for _, val := range scannedValues {
		parts := strings.Split(val, "_")
		if len(parts) < 3 {
			continue
		}

		qty := 1
		if len(parts) == 4 {
			qty, _ = strconv.Atoi(parts[3])
		}

		item := ScanItem{
			Raw:      val,
			Material: strings.ToUpper(parts[0]),
			Movement: strings.ToLower(parts[1]),
			BinID:    func() int { i, _ := strconv.Atoi(parts[2]); return i }(),
			Qty:      qty,
		}
		groupedScans[item.Material] = append(groupedScans[item.Material], item)
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
		return
	}

	defer tx.Rollback()

	for materialCode, items := range groupedScans {
		var m Material

		err := tx.QueryRow(`
            SELECT id, pack_quantity, max_bin_qty, current_quantity,
                   min_bin_qty, product_type, vendor_stock,
                   vendor_code, open_po
            FROM materials
            WHERE material_code ILIKE $1
            FOR UPDATE`,
			materialCode,
		).Scan(
			&m.ID, &m.PackQuantity, &m.MaxBinQty, &m.CurrentQuantity,
			&m.MinBinQty, &m.ProductType, &m.VendorStock,
			&m.VendorCode, &m.OpenPO,
		)

		if err != nil {
			log.Printf("Material %s tidak ditemukan atau gagal lock: %v", materialCode, err)
			continue
		}

		if role == "Vendor" && m.VendorCode != companyName {
			c.JSON(http.StatusForbidden, gin.H{"error": "Vendor tidak boleh scan material vendor lain (" + materialCode + ")"})
			return
		}

		totalSOHChange := 0
		totalVendorChange := 0
		totalPOChange := 0

		type HistoryLog struct {
			MovementType string
			Change       int
			OldQty       int
			NewQty       int
			Notes        string
			BinID        int
		}
		pendingLogs := []HistoryLog{}

		oldSOHBase := m.CurrentQuantity
		oldVendorBase := m.VendorStock

		if strings.ToLower(m.ProductType) == "special" {

			// Safety check: Pack Quantity tidak boleh 0
			if m.PackQuantity <= 0 {
				m.PackQuantity = 1
			}

			for _, item := range items {
				// Qty scan (default 1 jika kosong)
				qtyMultiplier := item.Qty
				if qtyMultiplier <= 0 {
					qtyMultiplier = 1
				}

				change := m.PackQuantity * qtyMultiplier

				if item.Movement == "in" {
					// Logic IN: SOH+, Vendor-
					if (m.VendorStock - totalVendorChange) < change {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Vendor stock %s tidak cukup", materialCode)})
						return
					}
					if (m.OpenPO - totalPOChange) < change {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Open PO %s tidak cukup", materialCode)})
						return
					}

					totalSOHChange += change
					totalVendorChange += change
					totalPOChange += change

					pendingLogs = append(pendingLogs, HistoryLog{
						MovementType: "Scan In (Special)",
						Change:       change,
						OldQty:       oldSOHBase + totalSOHChange - change,
						NewQty:       oldSOHBase + totalSOHChange,
						Notes:        fmt.Sprintf("Scan In Pack (Qty: %d)", qtyMultiplier),
						BinID:        0, // NULL
					})
					// Log Pengurangan Vendor
					pendingLogs = append(pendingLogs, HistoryLog{
						MovementType: "Scan In Vendor",
						Change:       -change,
						OldQty:       oldVendorBase - (totalVendorChange - change),
						NewQty:       oldVendorBase - totalVendorChange,
						Notes:        "Auto Deduct Vendor",
						BinID:        0,
					})

				} else {
					// Logic OUT: SOH-
					if (oldSOHBase + totalSOHChange) < change {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Stok %s tidak cukup", materialCode)})
						return
					}

					totalSOHChange -= change

					pendingLogs = append(pendingLogs, HistoryLog{
						MovementType: "Scan Out (Special)",
						Change:       -change,
						OldQty:       oldSOHBase + totalSOHChange + change,
						NewQty:       oldSOHBase + totalSOHChange,
						Notes:        fmt.Sprintf("Scan Out Pack (Qty: %d)", qtyMultiplier),
						BinID:        0, // NULL
					})
				}
			}

		} else {
			// ==========================================
			// LOGIC KANBAN/NORMAL (Tidak berubah)
			// ==========================================
			for _, item := range items {
				var currentBinStock, maxBinStock int
				// Cek Bin Fisik
				err = tx.QueryRow(`
                    SELECT current_bin_stock, max_bin_stock FROM material_bins
                    WHERE material_id = $1 AND bin_sequence_id = $2 FOR UPDATE`,
					m.ID, item.BinID,
				).Scan(&currentBinStock, &maxBinStock)

				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bin %d tidak ditemukan", item.BinID)})
					return
				}

				var change int

				if item.Movement == "in" {
					change = maxBinStock
					if currentBinStock > 0 {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Bin %d penuh", item.BinID)})
						return
					}
					if (m.VendorStock - totalVendorChange) < change {
						c.JSON(http.StatusConflict, gin.H{"error": "Vendor stock kurang"})
						return
					}
					// Update visual bin fisik
					tx.Exec(`UPDATE material_bins SET current_bin_stock = $1 WHERE material_id=$2 AND bin_sequence_id=$3`, change, m.ID, item.BinID)

					totalSOHChange += change
					totalVendorChange += change
					totalPOChange += change

					pendingLogs = append(pendingLogs, HistoryLog{
						MovementType: "Scan In", Change: change, OldQty: oldSOHBase + totalSOHChange - change, NewQty: oldSOHBase + totalSOHChange, Notes: fmt.Sprintf("Bin %d", item.BinID), BinID: item.BinID,
					})
					pendingLogs = append(pendingLogs, HistoryLog{
						MovementType: "Scan In Vendor", Change: -change, OldQty: oldVendorBase - (totalVendorChange - change), NewQty: oldVendorBase - totalVendorChange, Notes: fmt.Sprintf("Bin %d", item.BinID), BinID: item.BinID,
					})

				} else {
					change = -(item.Qty * m.PackQuantity)
					if (currentBinStock + change) < 0 {
						c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Stok Bin %d kurang", item.BinID)})
						return
					}
					// Update visual bin fisik
					tx.Exec(`UPDATE material_bins SET current_bin_stock = current_bin_stock + $1 WHERE material_id=$2 AND bin_sequence_id=$3`, change, m.ID, item.BinID)

					totalSOHChange += change
					pendingLogs = append(pendingLogs, HistoryLog{
						MovementType: "Scan Out", Change: change, OldQty: oldSOHBase + totalSOHChange - change, NewQty: oldSOHBase + totalSOHChange, Notes: fmt.Sprintf("Bin %d", item.BinID), BinID: item.BinID,
					})
				}
			}
		}

		m.CurrentQuantity += totalSOHChange
		m.VendorStock -= totalVendorChange
		m.OpenPO -= totalPOChange

		_, err = tx.Exec(`
            UPDATE materials
            SET current_quantity = $1,
                vendor_stock = $2,
                open_po = $3
            WHERE id = $4`,
			m.CurrentQuantity,
			m.VendorStock,
			m.OpenPO,
			m.ID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update total stok material"})
			return
		}

		for _, logItem := range pendingLogs {

			var binIdArg interface{}
			if logItem.BinID == 0 {
				binIdArg = nil
			} else {
				binIdArg = logItem.BinID
			}

			_, err = tx.Exec(`
                INSERT INTO stock_movements
                    (material_id, material_code, movement_type,
                     quantity_change, old_quantity, new_quantity,
                     pic, notes, bin_sequence_id)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            `,
				m.ID,
				materialCode,
				logItem.MovementType,
				logItem.Change,
				logItem.OldQty,
				logItem.NewQty,
				pic,
				logItem.Notes,
				binIdArg,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mencatat history"})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scan berhasil"})
}

func blockMaterial(c *gin.Context) {
	id := c.Param("id")

	var currentType string
	err := db.QueryRow("SELECT product_type FROM materials WHERE id = $1", id).Scan(&currentType)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Material tidak ditemukan"})
		return
	}

	if currentType == "block" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Material sudah diblock"})
		return
	}

	_, err = db.Exec(`
        UPDATE materials 
        SET previous_product_type = product_type, 
            product_type = 'block' 
        WHERE id = $1`, id)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memblokir material"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Material berhasil diblock"})
}

func unblockMaterial(c *gin.Context) {
	id := c.Param("id")

	_, err := db.Exec(`
        UPDATE materials 
        SET product_type = COALESCE(previous_product_type, 'kanban'), 
            previous_product_type = NULL 
        WHERE id = $1`, id)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal unblock material"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Material berhasil di-unblock"})
}
func getMaterialStatus(c *gin.Context) {
	materialCode := c.Query("code")
	if materialCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query 'code' dibutuhkan"})
		return
	}

	var m Material

	err := db.QueryRow(
		`SELECT id, pack_quantity, max_bin_qty, min_bin_qty, 
                current_quantity, product_type, vendor_stock, open_po
         FROM materials 
         WHERE material_code ILIKE $1`,
		materialCode,
	).Scan(
		&m.ID, &m.PackQuantity, &m.MaxBinQty, &m.MinBinQty,
		&m.CurrentQuantity, &m.ProductType,
		&m.VendorStock, &m.OpenPO,
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

	bins := make([]MaterialBin, 0)

	// Jika tipe "special", bins mungkin kosong, tapi query tidak akan error, cuma return kosong.
	binRows, err := db.Query(
		`SELECT id, material_id, bin_sequence_id, max_bin_stock, current_bin_stock
         FROM material_bins 
         WHERE material_id = $1 
         ORDER BY bin_sequence_id`,
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
		if err := binRows.Scan(&b.ID, &b.MaterialID, &b.BinSequenceID,
			&b.MaxBinStock, &b.CurrentBinStock); err != nil {
			log.Printf("Error scanning bin for %s: %v", materialCode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai bin"})
			return
		}
		bins = append(bins, b)
	}

	quantityPerBin := m.PackQuantity
	if len(bins) > 0 {
		quantityPerBin = bins[0].MaxBinStock
	}

	predictedMovement := "IN"
	if m.CurrentQuantity >= m.MaxBinQty {
		predictedMovement = "OUT"
	}
	// Logic predicted movement untuk special mungkin beda, tapi logic dasar SOH >= Max (OUT) masih valid sebagai indikator

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
		OpenPO:            m.OpenPO,
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

	// Logic special update
	if m.ProductType == "special" {
		if m.PackQuantity <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity wajib > 0 untuk special consumable"})
			return
		}
		m.Bins = []MaterialBin{} // Wipe bins logic
	}

	var oldQty int
	var oldVendorStock int
	var oldOpenPO int
	var oldVendorCode string

	err := db.QueryRow(
		"SELECT current_quantity, vendor_stock, open_po, vendor_code FROM materials WHERE id = $1",
		id,
	).Scan(&oldQty, &oldVendorStock, &oldOpenPO, &oldVendorCode)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Material tidak ditemukan"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memverifikasi data lama"})
		return
	}

	if role == "Vendor" {
		m.VendorCode = companyName
	}

	stockChanged := m.CurrentQuantity != oldQty
	vendorStockChanged := m.VendorStock != oldVendorStock
	openPOChanged := m.OpenPO != oldOpenPO

	if (stockChanged || vendorStockChanged || openPOChanged) && m.PIC == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PIC wajib diisi jika ada perubahan stok/PO"})
		return
	}

	// Validasi jika BUKAN special
	if m.ProductType != "special" {
		if m.PackQuantity <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Pack Quantity harus > 0"})
			return
		}
		if m.MaxBinQty < m.MinBinQty {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty tidak boleh lebih kecil dari Min Bin Qty"})
			return
		}
		if m.ProductType == "kanban" && m.MaxBinQty > 0 && m.MaxBinQty%m.PackQuantity != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Max Qty harus kelipatan Pack Qty (Kanban)"})
			return
		}

		if len(m.Bins) > 0 {
			calculatedTotal := 0
			for _, bin := range m.Bins {
				if bin.CurrentBinStock < 0 {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Stok bin tidak boleh negatif"})
					return
				}
				calculatedTotal += bin.CurrentBinStock
			}
			if calculatedTotal != m.CurrentQuantity {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Inkonsistensi: Total Stok (%d) != Jumlah Stok di Bin (%d)", m.CurrentQuantity, calculatedTotal)})
				return
			}
		}
	} else {
		// Validasi jika SPECIAL
		// Pastikan Current Quantity kelipatan Pack Quantity (sesuai constraint DB check_current_quantity_logic)
		if m.PackQuantity > 0 && m.CurrentQuantity%m.PackQuantity != 0 {
			// Opsional: kita bisa toleransi atau reject. Sebaiknya reject jika ingin strik.
			// Tapi karena user bisa edit manual, kita peringatkan saja atau biarkan constraint DB yang handle.
		}
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
		return
	}
	defer tx.Rollback()

	if stockChanged {
		if m.ProductType == "special" {
			// Logika edit simple untuk special
			change := m.CurrentQuantity - oldQty
			tx.Exec(
				`INSERT INTO stock_movements 
                 (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
                 VALUES ($1, $2, 'Edit (Special)', $3, $4, $5, $6, 'Manual Edit Special Pack', NULL)`,
				id, m.MaterialCode, change, oldQty, m.CurrentQuantity, m.PIC,
			)
		} else {
			// Logika edit existing dengan Bin
			oldBinMap := make(map[int]int)
			binRows, err := tx.Query("SELECT bin_sequence_id, current_bin_stock FROM material_bins WHERE material_id = $1", id)
			if err == nil {
				for binRows.Next() {
					var bSeq, bStk int
					binRows.Scan(&bSeq, &bStk)
					oldBinMap[bSeq] = bStk
				}
				binRows.Close()
			}

			if len(m.Bins) > 0 {
				binsLogged := 0
				for _, newBin := range m.Bins {
					oldStock := oldBinMap[newBin.BinSequenceID]
					diff := newBin.CurrentBinStock - oldStock

					if diff != 0 {
						_, errLog := tx.Exec(
							`INSERT INTO stock_movements 
                         (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
                         VALUES ($1, $2, 'Edit', $3, $4, $5, $6, $7, $8)`,
							id, m.MaterialCode, diff, oldStock, newBin.CurrentBinStock, m.PIC, "Manual Edit per Bin", newBin.BinSequenceID,
						)
						if errLog != nil {
							log.Printf("Error log bin movement: %v", errLog)
						} else {
							binsLogged++
						}
					}
				}

				if binsLogged == 0 {
					change := m.CurrentQuantity - oldQty
					tx.Exec(
						`INSERT INTO stock_movements 
                     (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
                     VALUES ($1, $2, 'Edit', $3, $4, $5, $6, 'Manual Edit Total', NULL)`,
						id, m.MaterialCode, change, oldQty, m.CurrentQuantity, m.PIC,
					)
				}
			} else {
				change := m.CurrentQuantity - oldQty
				tx.Exec(
					`INSERT INTO stock_movements 
                 (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes, bin_sequence_id)
                 VALUES ($1, $2, 'Edit', $3, $4, $5, $6, 'Manual Edit (No Bin Data)', NULL)`,
					id, m.MaterialCode, change, oldQty, m.CurrentQuantity, m.PIC,
				)
			}
		}
	}

	if vendorStockChanged {
		change := m.VendorStock - oldVendorStock
		tx.Exec(
			`INSERT INTO stock_movements 
             (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes)
             VALUES ($1, $2, 'Edit Vendor', $3, $4, $5, $6, 'Edit Vendor Stock')`,
			id, m.MaterialCode, change, oldVendorStock, m.VendorStock, m.PIC,
		)
	}

	_, err = tx.Exec(
		`UPDATE materials SET 
            material_code = $1, material_description = $2, location = $3, 
            pack_quantity = $4, max_bin_qty = $5, min_bin_qty = $6, 
            vendor_code = $7, current_quantity = $8, product_type = $9,
            vendor_stock = $10, open_po = $11
        WHERE id = $12`,
		m.MaterialCode, m.MaterialDescription, m.Location,
		m.PackQuantity, m.MaxBinQty, m.MinBinQty,
		m.VendorCode, m.CurrentQuantity, m.ProductType,
		m.VendorStock, m.OpenPO,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update material: " + err.Error()})
		return
	}

	// Selalu hapus bin lama dulu (aman untuk semua tipe)
	_, err = tx.Exec("DELETE FROM material_bins WHERE material_id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal reset bin lama"})
		return
	}

	// Insert bin baru hanya jika bukan special dan ada datanya
	if m.ProductType != "special" && len(m.Bins) > 0 {
		stmt, err := tx.Prepare(`
            INSERT INTO material_bins (material_id, bin_sequence_id, max_bin_stock, current_bin_stock)
            VALUES ($1, $2, $3, $4)
        `)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal prepare insert bin"})
			return
		}
		defer stmt.Close()

		for _, bin := range m.Bins {
			_, err := stmt.Exec(id, bin.BinSequenceID, bin.MaxBinStock, bin.CurrentBinStock)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal insert bin baru: " + err.Error()})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit transaksi"})
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

	_, err = tx.Exec("DELETE FROM stock_movements WHERE material_id = $1", id)
	if err != nil {
		log.Printf("Error deleting stock movements: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus histori material"})
		return
	}

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit penghapusan material"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Material berhasil dihapus (stok 0)"})
}

func recordDownload(c *gin.Context) {
	var req DownloadLogRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username dibutuhkan"})
		return
	}

	_, err := db.Exec(
		`INSERT INTO download_logs (username) VALUES ($1)`,
		req.Username,
	)

	if err != nil {
		log.Printf("Error logging download: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mencatat log download"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Log download berhasil dicatat"})
}

func getLastDownload(c *gin.Context) {
	var logEntry DownloadLog

	err := db.QueryRow(
		`SELECT username, timestamp FROM download_logs
         ORDER BY timestamp DESC
         LIMIT 1`,
	).Scan(&logEntry.Username, &logEntry.Timestamp)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusOK, nil)
			return
		}
		log.Printf("Error fetching last download log: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil log terakhir"})
		return
	}

	c.JSON(http.StatusOK, logEntry)
}

func smartImportMaterial(c *gin.Context) {

	bodyBytes, errRead := c.GetRawData()
	if errRead != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Gagal membaca body request"})
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	log.Printf("📥 Smart Import Payload: %s", string(bodyBytes))

	var req SmartMaterialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Bind Error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Format data salah: " + err.Error()})
		return
	}

	req.MaterialCode = strings.ToUpper(strings.TrimSpace(req.MaterialCode))

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB Transaction failed"})
		return
	}
	defer tx.Rollback()

	var existingID int
	var oldQty int

	err = tx.QueryRow(`
        SELECT id, current_quantity 
        FROM materials WHERE material_code = $1`, req.MaterialCode).Scan(&existingID, &oldQty)

	if err != nil && err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB Error check material"})
		return
	}

	safePackQty := 1
	if req.PackQuantity != nil && *req.PackQuantity > 0 {
		safePackQty = *req.PackQuantity
	}

	safeMinBinQty := 1
	if req.MinBinQty != nil && *req.MinBinQty > 0 {
		safeMinBinQty = *req.MinBinQty
	}

	safeMaxBinQty := 1
	if req.MaxBinQty != nil && *req.MaxBinQty > 0 {
		safeMaxBinQty = *req.MaxBinQty
	}

	if safeMaxBinQty < safePackQty {
		safeMaxBinQty = safePackQty
	}

	// Override product type logic in case of import quirks
	// If product type is special, ensure bins are empty later
	isSpecial := req.ProductType == "special"

	if err == sql.ErrNoRows {
		log.Println("✨ Mode: CREATE NEW MATERIAL ->", req.MaterialCode)

		desc := ""
		if req.MaterialDescription != nil {
			desc = *req.MaterialDescription
		}
		loc := ""
		if req.Location != nil {
			loc = *req.Location
		}
		vend := ""
		if req.VendorCode != nil {
			vend = *req.VendorCode
		}
		curQty := 0
		if req.CurrentQuantity != nil {
			curQty = *req.CurrentQuantity
		}

		err = tx.QueryRow(`
            INSERT INTO materials (
                material_code, material_description, location,
                pack_quantity, max_bin_qty, min_bin_qty,
                vendor_code, current_quantity, product_type, vendor_stock, open_po
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 0)
            RETURNING id`,
			req.MaterialCode, desc, loc,
			safePackQty, safeMaxBinQty, safeMinBinQty,
			vend, curQty, req.ProductType,
		).Scan(&existingID)

		if err != nil {
			log.Printf("❌ Insert Material Error: %v", err)
			if strings.Contains(err.Error(), "check_positive_quantities") {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database melarang nilai 0. Coba matikan constraint DB atau hubungi admin."})
				return
			}
			if strings.Contains(err.Error(), "foreign key") {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Vendor '%s' tidak terdaftar", vend)})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal insert: " + err.Error()})
			return
		}

		if !isSpecial {
			if len(req.Bins) > 0 {
				stmt, _ := tx.Prepare(`INSERT INTO material_bins (material_id, bin_sequence_id, max_bin_stock, current_bin_stock) VALUES ($1,$2,$3,$4)`)
				defer stmt.Close()
				for _, bin := range req.Bins {
					stmt.Exec(existingID, bin.BinSequenceID, bin.MaxBinStock, bin.CurrentBinStock)
				}
			} else if req.ProductType == "kanban" {

				if safeMaxBinQty > 0 && safePackQty > 0 {
					totalBins := safeMaxBinQty / safePackQty
					stmt, _ := tx.Prepare(`INSERT INTO material_bins (material_id, bin_sequence_id, max_bin_stock, current_bin_stock) VALUES ($1,$2,$3,0)`)
					defer stmt.Close()
					for i := 1; i <= totalBins; i++ {
						stmt.Exec(existingID, i, safePackQty)
					}
				}
			}
		}

		if curQty > 0 {
			tx.Exec(`INSERT INTO stock_movements (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes) 
                     VALUES ($1, $2, 'Initial Import', $3, 0, $3, 'System', 'Smart Import')`, existingID, req.MaterialCode, curQty)
		}

	} else {
		log.Printf("✏️ Mode: UPDATE EXISTING MATERIAL (ID: %d)", existingID)

		query := "UPDATE materials SET "
		params := []interface{}{}
		paramID := 1

		addParam := func(val interface{}, fieldName string) {
			query += fmt.Sprintf("%s = $%d, ", fieldName, paramID)
			params = append(params, val)
			paramID++
		}

		if req.MaterialDescription != nil {
			addParam(*req.MaterialDescription, "material_description")
		}
		if req.Location != nil {
			addParam(*req.Location, "location")
		}
		if req.VendorCode != nil {
			addParam(*req.VendorCode, "vendor_code")
		}
		if req.CurrentQuantity != nil {
			addParam(*req.CurrentQuantity, "current_quantity")
		}
		if req.ProductType != "" {
			addParam(req.ProductType, "product_type")
		}

		structureChanged := false

		if req.PackQuantity != nil {
			val := *req.PackQuantity
			if val <= 0 {
				val = 1
			}
			addParam(val, "pack_quantity")
			structureChanged = true
		}
		if req.MaxBinQty != nil {
			val := *req.MaxBinQty
			if val <= 0 {
				val = 1
			}
			addParam(val, "max_bin_qty")
			structureChanged = true
		}
		if req.MinBinQty != nil {
			val := *req.MinBinQty
			if val <= 0 {
				val = 1
			}
			addParam(val, "min_bin_qty")
			structureChanged = true
		}

		if len(params) > 0 {
			query = strings.TrimSuffix(query, ", ")
			query += fmt.Sprintf(" WHERE id = $%d", paramID)
			params = append(params, existingID)

			_, err = tx.Exec(query, params...)
			if err != nil {
				log.Printf("❌ Update Query Error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update: " + err.Error()})
				return
			}
		}

		if req.CurrentQuantity != nil && *req.CurrentQuantity != oldQty {
			diff := *req.CurrentQuantity - oldQty
			tx.Exec(`INSERT INTO stock_movements (material_id, material_code, movement_type, quantity_change, old_quantity, new_quantity, pic, notes) 
                     VALUES ($1, $2, 'Edit Import', $3, $4, $5, 'System', 'Smart Import Update')`,
				existingID, req.MaterialCode, diff, oldQty, *req.CurrentQuantity)
		}

		if isSpecial {
			// If switched to special, delete all bins
			tx.Exec("DELETE FROM material_bins WHERE material_id = $1", existingID)
		} else if structureChanged && len(req.Bins) > 0 {
			tx.Exec("DELETE FROM material_bins WHERE material_id = $1", existingID)
			stmt, _ := tx.Prepare(`INSERT INTO material_bins (material_id, bin_sequence_id, max_bin_stock, current_bin_stock) VALUES ($1,$2,$3,$4)`)
			defer stmt.Close()
			for _, bin := range req.Bins {
				stmt.Exec(existingID, bin.BinSequenceID, bin.MaxBinStock, bin.CurrentBinStock)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Commit failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Success", "id": existingID})
}
