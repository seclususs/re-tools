# BUILD INSTRUCTIONS

## 1. Buat Virtual Environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

**Windows (CMD):**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Instal `maturin`

```bash
pip install maturin
```

## 3. Build Rust Crate

```bash
cd core
cargo build --release
```

## 4. Integrasi Python

```bash
maturin develop --release
```

## 5. Konfigurasi CMake

```bash
cd ..
cmake -S . -B build
```

## 6. Build

```bash
cmake --build build
```

## 7. Jalankan Test

```bash
cd build
ctest
```