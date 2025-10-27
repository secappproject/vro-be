DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS project_category;
DROP TYPE IF EXISTS busbar_status;
DROP TYPE IF EXISTS tracking_status;
DROP TYPE IF EXISTS user_role;

CREATE TYPE project_category AS ENUM ('PIX', 'MCZ');
CREATE TYPE busbar_status AS ENUM ('Punching/Bending', 'Plating', 'Heatshrink', 'Done');
CREATE TYPE user_role AS ENUM ('Admin', 'PIC', 'Production Planning', 'External/Vendor');

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role user_role NOT NULL,
    company_name VARCHAR(100),
    vendor_type VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,
    wbs VARCHAR(100) UNIQUE NOT NULL,
    category project_category,
    plan_start DATE NOT NULL,
    quantity INTEGER NOT NULL,
    vendor_panel VARCHAR(100),
    vendor_busbar VARCHAR(100),
    panel_progress INTEGER DEFAULT 0 CHECK (panel_progress >= 0 AND panel_progress <= 100),
    status_busbar busbar_status DEFAULT 'Punching/Bending',

    fat_start DATE,
    plan_delivery_basic_kit_panel DATE,
    plan_delivery_basic_kit_busbar DATE,
    actual_delivery_basic_kit_panel DATE,
    actual_delivery_basic_kit_busbar DATE,
    plan_delivery_accessories_panel DATE,
    plan_delivery_accessories_busbar DATE,
    actual_delivery_accessories_panel DATE,
    actual_delivery_accessories_busbar DATE,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_projects_updated_at
BEFORE UPDATE ON projects
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

INSERT INTO projects (
    project_name, wbs, category, plan_start, quantity, vendor_panel, vendor_busbar,
    panel_progress, status_busbar,
    fat_start, -- FAT Start dummy
    plan_delivery_basic_kit_panel, -- Otomatis H+7 dari plan_start
    plan_delivery_basic_kit_busbar, -- Otomatis H+7 dari plan_start
    plan_delivery_accessories_panel, -- Otomatis H+7 dari fat_start
    plan_delivery_accessories_busbar -- Otomatis H+7 dari fat_start
) VALUES
('Project Alpha', 'WBS-001', 'PIX', '2025-11-01', 10, 'ABACUS', 'Triakarya', 0, 'Punching/Bending',
 '2025-11-15', -- FAT Start dummy (plan_start + 14 hari)
 '2025-11-08', -- plan_delivery_basic_kit (plan_start + 7 hari)
 '2025-11-08', -- plan_delivery_basic_kit (plan_start + 7 hari)
 '2025-11-22', -- plan_delivery_accessories (fat_start + 7 hari)
 '2025-11-22'  -- plan_delivery_accessories (fat_start + 7 hari)
),
('Project Beta', 'WBS-002', 'MCZ', '2025-11-05', 5, 'UMEDA', 'Globalindo', 25, 'Plating',
 '2025-11-19', -- FAT Start dummy
 '2025-11-12', -- plan_delivery_basic_kit
 '2025-11-12', -- plan_delivery_basic_kit
 '2025-11-26', -- plan_delivery_accessories
 '2025-11-26'  -- plan_delivery_accessories
),
('Project Gamma', 'WBS-003', 'PIX', '2025-11-10', 8, 'GAA', 'Presisi', 0, 'Punching/Bending',
 '2025-11-24', -- FAT Start dummy
 '2025-11-17', -- plan_delivery_basic_kit
 '2025-11-17', -- plan_delivery_basic_kit
 '2025-12-01', -- plan_delivery_accessories
 '2025-12-01'  -- plan_delivery_accessories
),
('Project Delta', 'WBS-004', 'MCZ', '2025-11-12', 12, 'ABACUS', 'Globalindo', 50, 'Heatshrink',
 '2025-11-26', -- FAT Start dummy
 '2025-11-19', -- plan_delivery_basic_kit
 '2025-11-19', -- plan_delivery_basic_kit
 '2025-12-03', -- plan_delivery_accessories
 '2025-12-03'  -- plan_delivery_accessories
),
('Project Epsilon', 'WBS-005', 'PIX', '2025-11-18', 7, 'UMEDA', 'Triakarya', 0, 'Punching/Bending',
 '2025-12-02', -- FAT Start dummy
 '2025-11-25', -- plan_delivery_basic_kit
 '2025-11-25', -- plan_delivery_basic_kit
 '2025-12-09', -- plan_delivery_accessories
 '2025-12-09'  -- plan_delivery_accessories
);

INSERT INTO users (username, password, role) VALUES
('admin', 'adminpass', 'Admin'),
('pic_user', 'picpass', 'PIC'),
('pp_user', 'pppass', 'Production Planning');

INSERT INTO users (username, password, role, company_name, vendor_type) VALUES
('vendor_abacus', 'abacuspass', 'External/Vendor', 'ABACUS', 'Panel'),
('vendor_umeda', 'umedapass', 'External/Vendor', 'UMEDA', 'Panel'),
('vendor_gaa', 'gaapass', 'External/Vendor', 'GAA', 'Panel'),
('vendor_triakarya', 'triapass', 'External/Vendor', 'Triakarya', 'Busbar'),
('vendor_global', 'globalpass', 'External/Vendor', 'Globalindo', 'Busbar'),
('vendor_presisi', 'presisipass', 'External/Vendor', 'Presisi', 'Busbar');

SELECT '✅ Tabel projects berhasil dibuat dan diisi data dummy.';