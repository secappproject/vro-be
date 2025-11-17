-- Hapus tabel yang mungkin ada sebelumnya (termasuk materials)
-- DROP TABLE IF EXISTS materials;
-- DROP TABLE IF EXISTS users;
-- DROP TABLE IF EXISTS vendors;
-- DROP TYPE IF EXISTS user_role;

-- tipe yang dibutuhkan (hanya user_role)
CREATE TYPE user_role AS ENUM ('Admin', 'PIC', 'Production Planning', 'External/Vendor');

--=================================================================
-- TABEL VENDORS
--=================================================================
CREATE TABLE vendors (
    id SERIAL PRIMARY KEY,
    company_name VARCHAR(100) UNIQUE NOT NULL, -- Ini akan jadi 'vendor_code' di tabel material
    vendor_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

--=================================================================
-- TABEL USERS (Sesuai skema Anda)
--=================================================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role user_role NOT NULL,
    company_name VARCHAR(100), -- Relasi ke vendors
    vendor_type VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

--=================================================================
-- TABEL MATERIALS
--=================================================================
CREATE TABLE materials (
    id SERIAL PRIMARY KEY,
    material_code VARCHAR(100) UNIQUE NOT NULL,
    material_description TEXT,
    location VARCHAR(100),
    
    -- Setting Kuantitas
    pack_quantity INT NOT NULL,  -- (Quantity per scan)
    max_bin_qty INT NOT NULL,    -- (Batas Penuh/Ijo)
    min_bin_qty INT NOT NULL,    -- (Batas Acuan Merah)
    
    -- Data Live
    current_quantity INT NOT NULL DEFAULT 0,
    
    -- Relasi ke Vendor
    vendor_code VARCHAR(100) NOT NULL,
    
    -- Constraint (Aturan Bisnis)
    CONSTRAINT fk_vendor
        FOREIGN KEY(vendor_code) 
        REFERENCES vendors(company_name)
        ON DELETE RESTRICT, -- Tidak bisa hapus vendor jika masih punya material

    -- Memastikan angka valid
    CONSTRAINT check_positive_quantities
        CHECK (pack_quantity > 0 AND max_bin_qty > 0 AND min_bin_qty >= 0),
        
    -- Memastikan max lebih besar dari min
    CONSTRAINT check_max_greater_than_min
        CHECK (max_bin_qty >= min_bin_qty),
        
    -- ATURAN KUNCI: Pack Quantity adalah kelipatan dari Max Quantity
    CONSTRAINT check_pack_is_factor_of_max
        CHECK (MOD(max_bin_qty, pack_quantity) = 0),

    -- ATURAN BARU (Opsional tapi direkomendasikan): Current Qty harus kelipatan Pack Qty
    CONSTRAINT check_current_is_multiple_of_pack
        CHECK (MOD(current_quantity, pack_quantity) = 0)
);

ALTER TABLE materials
DROP CONSTRAINT fk_vendor;

--=================================================================
-- FUNGSI & TRIGGER
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

ALTER TABLE materials
ADD COLUMN product_type VARCHAR(20) NOT NULL DEFAULT 'kanban';

CREATE TABLE material_bins (
    id SERIAL PRIMARY KEY,
    material_id INT NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
    
    bin_sequence_id INT NOT NULL, 
    
    max_bin_stock INT NOT NULL,
    
    current_bin_stock INT NOT NULL DEFAULT 0,
    
    UNIQUE(material_id, bin_sequence_id)
);

ALTER TABLE materials
DROP CONSTRAINT IF EXISTS check_current_is_multiple_of_pack;
ALTER TABLE materials
ADD CONSTRAINT check_current_quantity_logic
CHECK (
    product_type = 'kanban' 
    OR 
    (product_type <> 'kanban' AND current_quantity % pack_quantity = 0)
);
ALTER TABLE materials
ADD COLUMN vendor_stock INT DEFAULT 0;
--=================================================================
-- DATA DUMMY (Vendors & Users)
--=================================================================
-- INSERT INTO vendors (company_name, vendor_type) VALUES
-- ('ABACUS', 'Panel'),
-- ('UMEDA', 'Panel'),
-- ('GAA', 'Panel'),
-- ('Triakarya', 'Busbar'),
-- ('Globalindo', 'Busbar'),
-- ('Presisi', 'Busbar');

-- INSERT INTO users (username, password, role) VALUES
-- ('admin', 'adminpass', 'Admin'),
-- ('pic_user', 'picpass', 'PIC'),
-- ('pp_user', 'pppass', 'Production Planning');

-- INSERT INTO users (username, password, role, company_name, vendor_type) VALUES
-- ('vendor_abacus', 'abacuspass', 'External/Vendor', 'ABACUS', 'Panel'),
-- ('vendor_umeda', 'umedapass', 'External/Vendor', 'UMEDA', 'Panel');


--=================================================================
-- DATA DUMMY (Materials)
-- Sesuai aturan: max_bin_qty HARUS habis dibagi pack_quantity
-- DAN current_quantity HARUS habis dibagi pack_quantity
--=================================================================
-- INSERT INTO materials 
--     (material_code, material_description, location, pack_quantity, max_bin_qty, min_bin_qty, vendor_code, current_quantity) 
-- VALUES
--     -- Skenario Normal (Min < Pack) -- DIPERBAIKI
--     ('PNL-AB-001', 'Panel Box 20x30', 'A-1', 50, 200, 20, 'ABACUS', 150), -- DIUBAH: 70 -> 150 (agar kelipatan 50)
--     -- (Stok 150. Scan OUT 1x -> Stok 100. Scan OUT 2x -> Stok 50. Stok 50 <= TitikMerah(50). TRIGGER)
    
--     -- Skenario Normal (Min > Pack)
--     ('PNL-UM-002', 'Panel Box 50x70', 'A-2', 10, 100, 30, 'UMEDA', 100),
--     -- (Stok 100 (FULL). Scan OUT 1x -> Stok 90. ... Scan OUT 7x -> Stok 30. Stok 30 <= TitikMerah(30). TRIGGER)

--     -- Skenario Penuh (Current = Max)
--     ('BUS-TR-001', 'Busbar Tembaga 5x20', 'B-1', 25, 250, 50, 'Triakarya', 250),
--     -- (Stok 250 (FULL). Scan IN akan ditolak oleh backend)

--     -- Skenario Stok di Titik Merah (Min = Pack)
--     ('BUS-GL-002', 'Busbar Tembaga 10x40', 'B-2', 30, 150, 30, 'Globalindo', 30),
--     -- (Stok 30. Sudah merah. Scan OUT 1x -> Stok 0. TRIGGER)
    
--     -- Skenario Stok Kosong
--     ('BUS-PR-003', 'Busbar Alumunium 3x10', 'B-3', 20, 200, 40, 'Presisi', 0),
--     -- (Stok 0. Merah)

--     -- Skenario 1 Pack = 1 Max
--     ('PNL-GAA-003', 'Panel Custom Assembly', 'A-3', 10, 10, 1, 'GAA', 10);
--     -- (Stok 10 (FULL). Scan OUT 1x -> Stok 0. Stok 0 <= TitikMerah(10). TRIGGER)


-- Pesan sukses
SELECT '✅ Tabel users, vendors, dan materials berhasil dibuat dan diisi data dummy (diperbaiki).';


-- Pastikan semua perintah dieksekusi dalam satu transaksi
BEGIN;

-- 1. Buat Tipe ENUM baru yang diinginkan
CREATE TYPE user_role_new AS ENUM ('Superuser', 'Admin', 'Vendor', 'Viewer');

-- 2. Hapus semua user KECUALI 'admin' yang akan dimigrasi
DELETE FROM users WHERE username != 'admin';

-- 3. Tambah kolom sementara (nullable) dengan Tipe ENUM baru
ALTER TABLE users ADD COLUMN role_new user_role_new;

-- 4. KOREKSI: Ubah username 'admin' -> 'superuser' DAN role-nya -> 'Superuser'
UPDATE users 
SET 
    username = 'superuser', -- Tambahkan baris ini
    role_new = 'Superuser' 
WHERE 
    username = 'admin';

-- 5. Hapus kolom 'role' yang lama (yang masih pakai ENUM lama 'user_role')
ALTER TABLE users DROP COLUMN role;

-- 6. Hapus Tipe ENUM yang lama (sekarang sudah tidak terpakai)
DROP TYPE user_role;

-- 7. Ubah nama kolom baru ('role_new') menjadi 'role'
ALTER TABLE users RENAME COLUMN role_new TO role;

-- 8. Ubah nama Tipe ENUM baru ('user_role_new') menjadi 'user_role' (nama standar)
ALTER TYPE user_role_new RENAME TO user_role;

-- 9. Pastikan kolom 'role' sekarang NOT NULL (karena 'superuser' sudah diisi)
ALTER TABLE users ALTER COLUMN role SET NOT NULL;

-- 10. Insert user-user baru sesuai permintaan
INSERT INTO users (username, password, role) VALUES 
('admin', 'adminpass', 'Admin'),
('viewer', 'viewerpass', 'Viewer');

-- (Asumsi vendor 'ABACUS' sudah ada dari data dummy sebelumnya)
INSERT INTO users (username, password, role, company_name, vendor_type) VALUES 
('vendor_abacus', 'vendorpass', 'Vendor', 'ABACUS', 'Panel');

-- Selesaikan transaksi
COMMIT;

SELECT '✅ Migrasi role user berhasil: User ''admin'' lama -> ''superuser'', user baru (admin, viewer, vendor) ditambahkan.';

INSERT INTO users (username, password, role, company_name, vendor_type)
SELECT 
    'vendor_' || v.company_name AS username,
    'vendorpass' AS password,
    'Vendor'::user_role AS role,
    v.company_name,
    v.vendor_type
FROM 
    vendors v
WHERE 
    NOT EXISTS (
        -- Cek apakah sudah ada user 'Vendor' dengan company_name ini
        SELECT 1 
        FROM users u 
        WHERE u.company_name = v.company_name AND u.role = 'Vendor'
    )
ON CONFLICT (username) DO NOTHING; -- Jika username 'vendor_...' sudah ada, lewati

DELETE FROM 
    vendors v
WHERE 
    -- Tidak ada user yang terkait dengan vendor ini
    NOT EXISTS (
        SELECT 1 
        FROM users u 
        WHERE u.company_name = v.company_name
    ) 
AND 
    -- Tidak ada material yang terkait dengan vendor ini
    NOT EXISTS (
        SELECT 1 
        FROM materials m 
        WHERE m.vendor_code = v.company_name
    );

UPDATE users
SET 
    username = 'vendor_' || TRIM(BOTH '_' FROM REGEXP_REPLACE(
        -- Ganti 2+ underscore jadi 1 (cth: 'cv__globalindo' -> 'cv_globalindo')
        REGEXP_REPLACE(
            -- Ganti semua non-alfanumerik jadi '_' (cth: 'cv. globalindo' -> 'cv__globalindo')
            LOWER(company_name), 
            '[^a-z0-9]', 
            '_', 
            'g'
        ), 
        '_{2,}', 
        '_', 
        'g'
    ))
WHERE 
    role = 'Vendor'
    AND company_name IS NOT NULL;


UPDATE users
SET 
    username = LOWER(
        array_to_string(
            (
                -- 3. Pisah nama yang sudah bersih menjadi array kata
                string_to_array(
                    -- 2. Hapus 'cv.' atau 'pt.' (case-insensitive) dari awal
                    TRIM(REGEXP_REPLACE(company_name, '^(cv\.|pt\.)\s*', '', 'i')), 
                    ' ' -- Pemisah adalah spasi
                )
            )[1:2], -- 4. Ambil hanya 2 elemen pertama dari array
            '_' -- 5. Gabungkan 2 elemen itu dengan '_'
        )
    )
WHERE 
    role = 'Vendor'
    AND company_name IS NOT NULL;


CREATE TABLE stock_movements (
    id SERIAL PRIMARY KEY,
    material_id INT NOT NULL REFERENCES materials(id),
    material_code VARCHAR(255) NOT NULL,
    movement_type VARCHAR(50) NOT NULL, -- Cth: 'Edit', 'Scan IN', 'Scan OUT'
    quantity_change INT NOT NULL,      -- Cth: +24, -12, -1
    old_quantity INT NOT NULL,
    new_quantity INT NOT NULL,
    pic VARCHAR(255) NOT NULL,         -- Siapa yang melakukan
    notes TEXT,                        -- Opsional, cth: 'Scan Bin 5'
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Opsional: Buat index untuk mempercepat query
CREATE INDEX idx_stock_movements_material_id ON stock_movements(material_id);
CREATE INDEX idx_stock_movements_timestamp ON stock_movements(timestamp);

ALTER TABLE stock_movements
ADD COLUMN bin_sequence_id INT NULL;

CREATE TABLE IF NOT EXISTS download_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE materials
ADD COLUMN open_po INT DEFAULT 0;