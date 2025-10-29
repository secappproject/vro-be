package main

import (
	"database/sql"
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
    ID                  int    `json:"id"`
    MaterialCode        string `json:"material" binding:"required"`    
    MaterialDescription string `json:"materialDescription"`
    Location            string `json:"lokasi"`
    PackQuantity        int    `json:"packQuantity" binding:"required"`
    MaxBinQty           int    `json:"maxBinQty" binding:"required"`
    MinBinQty           int    `json:"minBinQty" binding:"required"`
    VendorCode          string `json:"vendorCode"`    
    CurrentQuantity     int    `json:"currentQuantity"`                  
}

type MaterialStatusResponse struct {
    PackQuantity        int    `json:"packQuantity"`
    MaxBinQty           int    `json:"maxBinQty"`
    MinBinQty           int    `json:"minBinQty"`
    CurrentQuantity     int    `json:"currentQuantity"`
    PredictedMovement string `json:"predictedMovement"`
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

    // sqlFile, err := os.ReadFile("init.sql")
    // if err != nil {
    //     fmt.Println("Skipping init.sql:", err)
    // } else {
    //     _, err = db.Exec(string(sqlFile))
    //     if err != nil {
    //         fmt.Println("Init.sql execution error:", err)
    //     } else {
    //         fmt.Println("Database initialized.")
    //     }
    // }

    router := gin.Default()
    router.RedirectTrailingSlash = true    
    // config := cors.DefaultConfig()
    // config.AllowOrigins = []string{"*"}
    // config.AllowMethods = []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"}
    // config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "X-User-Role"}
    config := cors.Config{
        AllowOrigins:     []string{"https://vro-fe.vercel.app", "http://localhost:3000","http://localhost:3001"},
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
               vendor_code, current_quantity 
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
        ); err != nil {
            log.Printf("Error scanning material: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data material"})
            return
        }
        materials = append(materials, m)
    }

    if err := rows.Err(); err != nil {
        log.Printf("Error during rows iteration: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Terjadi kesalahan saat memproses data"})
        return
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

    m.CurrentQuantity = 0

    err := db.QueryRow(
        `INSERT INTO materials (
            material_code, material_description, location, 
            pack_quantity, max_bin_qty, min_bin_qty, 
            vendor_code, current_quantity
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id`,
        m.MaterialCode, m.MaterialDescription, m.Location,
        m.PackQuantity, m.MaxBinQty, m.MinBinQty,
        m.VendorCode, m.CurrentQuantity,
    ).Scan(&m.ID)

    if err != nil {
        log.Printf("Error creating material: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat material: " + err.Error()})
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
    _, err := db.Exec(
        `UPDATE materials SET 
            material_code = $1, 
            material_description = $2, 
            location = $3, 
            pack_quantity = $4, 
            max_bin_qty = $5, 
            min_bin_qty = $6, 
            vendor_code = $7,
            current_quantity = $8 
         WHERE id = $9`,
        m.MaterialCode, m.MaterialDescription, m.Location,
        m.PackQuantity, m.MaxBinQty, m.MinBinQty,
        m.VendorCode,
        m.CurrentQuantity, 
        id, 
    )

    if err != nil {
        log.Printf("Error updating material: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update material: " + err.Error()})
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

    _, err = db.Exec("DELETE FROM materials WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting material: %v", err)
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
            `SELECT id, pack_quantity, max_bin_qty, current_quantity, min_bin_qty, material_code
             FROM materials 
             WHERE material_code = $1 
             FOR UPDATE`,
            materialCode,
        ).Scan(&m.ID, &m.PackQuantity, &m.MaxBinQty, &m.CurrentQuantity, &m.MinBinQty, &m.MaterialCode)

        if err != nil {
            if errors.Is(err, sql.ErrNoRows) {
                c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Material tidak ditemukan: %s (dari scan '%s')", materialCode, scannedValue)})
                return
            }
            log.Printf("Error querying material %s: %v", materialCode, err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data material"})
            return
        }

        var newQuantity int
        if scanType == "IN" {
            newQuantity = m.CurrentQuantity + m.PackQuantity
            if newQuantity > m.MaxBinQty {
                c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan IN (%s): Bin penuh (akan menjadi %d dari max %d)", m.MaterialCode, newQuantity, m.MaxBinQty)})
                return
            }
        } else { 
            newQuantity = m.CurrentQuantity - m.PackQuantity
            if newQuantity < 0 {
                c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Gagal Scan OUT (%s): Stok tidak mencukupi (akan menjadi %d)", m.MaterialCode, newQuantity)})
                return
            }
        }

        _, err = tx.Exec(
            "UPDATE materials SET current_quantity = $1 WHERE id = $2",
            newQuantity, m.ID,
        )
        if err != nil {
            log.Printf("Error updating stock for %s: %v", m.MaterialCode, err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update stok"})
            return
        }

        reorderPoint := m.MinBinQty
        if m.PackQuantity > m.MinBinQty {
            reorderPoint = m.PackQuantity 
        }

        if scanType == "OUT" && newQuantity <= reorderPoint {
            log.Printf("--- TRIGGER VRO UNTUK: %s (Stok: %d, Titik Merah: %d) ---", m.MaterialCode, newQuantity, reorderPoint)
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
