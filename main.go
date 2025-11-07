package main

import (
    "database/sql"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
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
    materialIDs := make([]interface{}, 0)
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
                WHERE material_id IN (?` + strings.Repeat(",?", len(materialIDs)-1) + `)
                ORDER BY material_id, bin_sequence_id
            `

        query = strings.Replace(query, "?", "$", -1)
        i := 1
        for strings.Contains(query, "$") {
            query = strings.Replace(query, "$", fmt.Sprintf("$%d", i), 1)
            i++
        }

        binRows, err := db.Query(query, materialIDs...)
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
    if m.MaxBinQty%m.PackQuantity != 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty harus merupakan kelipatan dari Pack Quantity"})
        return
    }

    if m.ProductType == "" {
        m.ProductType = "kanban"
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

    if m.ProductType != "kanban" {
        totalBins := m.MaxBinQty / m.PackQuantity
        if totalBins > 0 {
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

            for i := 1; i <= totalBins; i++ {
                _, err := stmt.Exec(m.ID, i, m.PackQuantity, 0)
                if err != nil {
                    log.Printf("Error inserting bin: %v", err)
                    c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat bin material"})
                    return
                }
                m.Bins = append(m.Bins, MaterialBin{
                    MaterialID:      m.ID,
                    BinSequenceID:   i,
                    MaxBinStock:     m.PackQuantity,
                    CurrentBinStock: 0,
                })
            }
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
	if m.MaxBinQty%m.PackQuantity != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Max Bin Qty harus merupakan kelipatan dari Pack Quantity"})
		return
	}

	if m.CurrentQuantity < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current Quantity tidak boleh negatif"})
		return
	}
	if m.CurrentQuantity > m.MaxBinQty {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Current Quantity (%d) tidak boleh melebihi Max Bin Qty (%d)", m.CurrentQuantity, m.MaxBinQty)})
		return
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

	_, err = tx.Exec("DELETE FROM material_bins WHERE material_id = $1", id)
	if err != nil {
		log.Printf("Error deleting old bins: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus bin lama"})
		return
	}

	if m.ProductType != "kanban" {
		totalBinsInPayload := m.MaxBinQty / m.PackQuantity
		
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

		var calculatedTotalStock int = 0

		if len(m.Bins) > 0 && len(m.Bins) == totalBinsInPayload {
			for _, bin := range m.Bins {
				if bin.CurrentBinStock > m.PackQuantity {
					tx.Rollback()
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Stok bin %d (%d) melebihi Pack Quantity (%d)", bin.BinSequenceId, bin.CurrentBinStock, m.PackQuantity)})
					return
				}
				if bin.CurrentBinStock < 0 {
					tx.Rollback()
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Stok bin %d (%d) tidak boleh negatif", bin.BinSequenceId, bin.CurrentBinStock)})
					return
				}

				_, err := stmt.Exec(id, bin.BinSequenceId, m.PackQuantity, bin.CurrentBinStock)
				if err != nil {
					log.Printf("Error inserting bin: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat bin material"})
					return
				}
				calculatedTotalStock += bin.CurrentBinStock
			}
		} else {
			currentStockRemaining := m.CurrentQuantity
			for i := 1; i <= totalBinsInPayload; i++ {
				var binStock int
				if currentStockRemaining >= m.PackQuantity {
					binStock = m.PackQuantity
					currentStockRemaining -= m.PackQuantity
				} else if currentStockRemaining > 0 {
					binStock = currentStockRemaining
					currentStockRemaining = 0
				} else {
					binStock = 0
				}

				_, err := stmt.Exec(id, i, m.PackQuantity, binStock)
				if err != nil {
					log.Printf("Error inserting bin (fallback): %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat bin material (fallback)"})
					return
				}
			}
			calculatedTotalStock = m.CurrentQuantity
		}
		
		if calculatedTotalStock != m.CurrentQuantity {
			tx.Rollback()
			log.Printf("Inkonsistensi stok: Total %d vs Kalkulasi Bin %d", m.CurrentQuantity, calculatedTotalStock)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Inkonsistensi data stok bin."})
			return
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
        var materialCode string
        var scanType string

        if strings.HasSuffix(strings.ToUpper(scannedValue), "_IN") {
            materialCode = scannedValue[:len(scannedValue)-3]
            scanType = "IN"
        } else if strings.HasSuffix(strings.ToUpper(scannedValue), "_OUT") {
            materialCode = scannedValue[:len(scannedValue)-4]
            scanType = "OUT"
        } else {
            c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Format scan salah: '%s'. Gunakan [MaterialID]_IN atau [MaterialID]_OUT", scannedValue)})
            return
        }

        if materialCode == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Material ID kosong dari scan: '%s'", scannedValue)})
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

        if m.ProductType == "kanban" {
            if scanType == "IN" {
                newTotalQuantity = m.CurrentQuantity + m.PackQuantity
                if newTotalQuantity > m.MaxBinQty {
                    c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s): Bin penuh (akan menjadi %d dari max %d)", m.MaterialCode, newTotalQuantity, m.MaxBinQty)})
                    return
                }
            } else {
                newTotalQuantity = m.CurrentQuantity - m.PackQuantity
                if newTotalQuantity < 0 {
                    c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s): Stok tidak mencukupi (akan menjadi %d)", m.MaterialCode, newTotalQuantity)})
                    return
                }
            }
        } else {
            if scanType == "IN" {
                var binToFillID int
                err := tx.QueryRow(
                    `SELECT id FROM material_bins
                     WHERE material_id = $1 AND current_bin_stock = 0
                     ORDER BY bin_sequence_id ASC
                     LIMIT 1
                     FOR UPDATE`,
                    m.ID,
                ).Scan(&binToFillID)

                if errors.Is(err, sql.ErrNoRows) {
                    c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s): Tidak ada bin kosong", m.MaterialCode)})
                    return
                }

                _, err = tx.Exec(
                    "UPDATE material_bins SET current_bin_stock = $1 WHERE id = $2",
                    m.PackQuantity,
                    binToFillID,
                )
                if err != nil {
                    log.Printf("Error updating bin stock for %s: %v", m.MaterialCode, err)
                    c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update stok bin"})
                    return
                }
                newTotalQuantity = m.CurrentQuantity + m.PackQuantity

            } else {
                var binToEmptyID int
                err := tx.QueryRow(
                    `SELECT id FROM material_bins
                     WHERE material_id = $1 AND current_bin_stock > 0
                     ORDER BY bin_sequence_id ASC
                     LIMIT 1
                     FOR UPDATE`,
                    m.ID,
                ).Scan(&binToEmptyID)

                if errors.Is(err, sql.ErrNoRows) {
                    c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s): Tidak ada bin yang berisi (stok habis)", m.MaterialCode)})
                    return
                }

                _, err = tx.Exec(
                    "UPDATE material_bins SET current_bin_stock = 0 WHERE id = $1",
                    binToEmptyID,
                )
                if err != nil {
                    log.Printf("Error updating bin stock for %s: %v", m.MaterialCode, err)
                    c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update stok bin"})
                    return
                }
                newTotalQuantity = m.CurrentQuantity - m.PackQuantity
            }
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

        reorderPoint := m.MinBinQty
        if m.PackQuantity > m.MinBinQty {
            reorderPoint = m.PackQuantity
        }

        if scanType == "OUT" && newTotalQuantity <= reorderPoint {
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
        `SELECT pack_quantity, max_bin_qty, min_bin_qty, current_quantity
         FROM materials 
         WHERE material_code = $1`,
        materialCode,
    ).Scan(&m.PackQuantity, &m.MaxBinQty, &m.MinBinQty, &m.CurrentQuantity)

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
        PackQuantity:        m.PackQuantity,
        MaxBinQty:           m.MaxBinQty,
        MinBinQty:           m.MinBinQty,
        CurrentQuantity:     m.CurrentQuantity,
        PredictedMovement: predictedMovement,
    }

    c.JSON(http.StatusOK, response)
}