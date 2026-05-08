--=================================================================
-- 1. BERSIHKAN DATABASE (OPSIONAL, AMAN UNTUK DEVICE BARU)
--=================================================================
DROP TABLE IF EXISTS email_logs CASCADE;
DROP TABLE IF EXISTS download_logs CASCADE;
DROP TABLE IF EXISTS stock_movements CASCADE;
DROP TABLE IF EXISTS material_bins CASCADE;
DROP TABLE IF EXISTS materials CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS vendors CASCADE;
DROP TYPE IF EXISTS user_role CASCADE;

--=================================================================
-- 2. TIPE DATA ENUM (BENTUK FINAL)
--=================================================================
CREATE TYPE user_role AS ENUM ('Superuser', 'Admin', 'Vendor', 'Viewer');

--=================================================================
-- 3. TABEL VENDORS
--=================================================================
CREATE TABLE vendors (
    id SERIAL PRIMARY KEY,
    company_name VARCHAR(100) UNIQUE NOT NULL, 
    vendor_type VARCHAR(50) NOT NULL,
    email VARCHAR(255) DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

--=================================================================
-- 4. TABEL USERS
--=================================================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role user_role NOT NULL,
    company_name VARCHAR(100), 
    vendor_type VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

--=================================================================
-- 5. TABEL MATERIALS (SEMUA KOLOM FINAL & CONSTRAINT)
--=================================================================
CREATE TABLE materials (
    id SERIAL PRIMARY KEY,
    material_code VARCHAR(100) UNIQUE NOT NULL,
    material_description TEXT,
    location VARCHAR(100),
    
    -- Setting Kuantitas
    pack_quantity INT NOT NULL,
    max_bin_qty INT NOT NULL,
    min_bin_qty INT NOT NULL,
    
    -- Data Live & Tipe Produk
    current_quantity INT NOT NULL DEFAULT 0,
    product_type VARCHAR(20) NOT NULL DEFAULT 'kanban',
    previous_product_type VARCHAR(50),
    vendor_stock INT DEFAULT 0,
    open_po INT DEFAULT 0,
    
    -- Fitur Tambahan
    remark_block TEXT,
    amu NUMERIC(10,2) DEFAULT 0,
    fmrs VARCHAR(10),
    coverage_month NUMERIC(10,2) DEFAULT 0,
    warning_status VARCHAR(20) DEFAULT 'safe',
    
    -- Relasi ke Vendor
    vendor_code VARCHAR(100) NOT NULL,
    
    -- Constraints (Tanpa FK ke vendors sesuai revisi terakhirmu)
    CONSTRAINT check_positive_quantities
        CHECK (pack_quantity > 0 AND max_bin_qty > 0 AND min_bin_qty >= 0),
        
    CONSTRAINT check_max_greater_than_min
        CHECK (max_bin_qty >= min_bin_qty),
        
    CONSTRAINT check_pack_is_factor_of_max
        CHECK (MOD(max_bin_qty, pack_quantity) = 0),

    CONSTRAINT check_current_quantity_logic
        CHECK (
            product_type = 'kanban' 
            OR 
            (product_type <> 'kanban' AND current_quantity % pack_quantity = 0)
        )
);

--=================================================================
-- 6. TABEL PENDUKUNG LAINNYA
--=================================================================
CREATE TABLE material_bins (
    id SERIAL PRIMARY KEY,
    material_id INT NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
    bin_sequence_id INT NOT NULL, 
    max_bin_stock INT NOT NULL,
    current_bin_stock INT NOT NULL DEFAULT 0,
    UNIQUE(material_id, bin_sequence_id)
);

CREATE TABLE stock_movements (
    id SERIAL PRIMARY KEY,
    material_id INT NOT NULL REFERENCES materials(id),
    material_code VARCHAR(255) NOT NULL,
    movement_type VARCHAR(50) NOT NULL,
    quantity_change INT NOT NULL,
    old_quantity INT NOT NULL,
    new_quantity INT NOT NULL,
    pic VARCHAR(255) NOT NULL,
    notes TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    bin_sequence_id INT NULL
);

CREATE INDEX idx_stock_movements_material_id ON stock_movements(material_id);
CREATE INDEX idx_stock_movements_timestamp ON stock_movements(timestamp);

CREATE TABLE download_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE email_logs (
    id SERIAL PRIMARY KEY,
    vendor_code VARCHAR(100),
    material_code VARCHAR(100),
    sent_at TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(50),
    error_message TEXT
);

--=================================================================
-- 7. FUNGSI & TRIGGER UNTUK UPDATE TIMESTAMP
--=================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_vendors_updated_at
BEFORE UPDATE ON vendors
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

--=================================================================
-- 8. INSERT INITIAL USERS (SUDAH DIPERBAIKI)
--=================================================================
INSERT INTO users (username, password, role) VALUES 
('superuser', 'adminpass', 'Superuser'),
('admin', 'adminpass', 'Admin'),
('viewer', 'viewerpass', 'Viewer');

-- Pesan Sukses
SELECT '✅ Database berhasil diinisialisasi untuk device baru dalam satu kali jalan.';