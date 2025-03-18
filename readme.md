# Session Manager Documentation

## Ikhtisar

Session Manager adalah sistem pengelolaan sesi berbasis browser yang sangat aman tanpa memerlukan database server. Dirancang untuk memberikan keamanan tingkat tinggi melalui implementasi teknik kriptografi modern, sistem ini memungkinkan penyimpanan data sesi secara aman di sisi klien dengan perlindungan terhadap berbagai serangan umum seperti session hijacking, CSRF, dan manipulasi data.

## Fitur

- **Enkripsi AES-GCM**: Mengimplementasikan standar enkripsi kuat untuk melindungi data sesi
- **Key Derivation via PBKDF2**: Meningkatkan keamanan dengan menggunakan fungsi turunan kunci yang aman
- **Fingerprint Perangkat**: Mencegah session hijacking dengan memvalidasi identitas perangkat
- **Proteksi Anti-CSRF**: Termasuk fungsi untuk menghasilkan dan memvalidasi token CSRF
- **Validasi Signature**: Memastikan integritas data dengan verifikasi signature
- **Validasi Checksum**: Lapisan tambahan untuk verifikasi data
- **Cookie Security**: Menetapkan flag Secure dan SameSite=Strict untuk meningkatkan keamanan cookie
- **Penanganan Kesalahan**: Sistem penanganan error yang komprehensif
- **Timeout Session**: Otomatis menghapus sesi yang tidak aktif

## Instalasi

```bash
npm install secure-session-manager
```

Atau tambahkan file `Session.ts` ke dalam proyek Anda.

## Penggunaan Dasar

### Menyimpan Data Sesi

```typescript
import Session from './path/to/Session';

// Menyimpan data sederhana
await Session.set('username', 'john_doe');

// Menyimpan objek
await Session.set('user', {
  id: 1,
  name: 'John Doe',
  role: 'admin'
});

// Menyimpan dengan waktu kedaluwarsa kustom (dalam hari)
await Session.set('temporaryData', { key: 'value' }, 1); // berlaku selama 1 hari
```

### Mengambil Data Sesi

```typescript
// Mengambil data sederhana
const username = await Session.get('username');
console.log(username); // 'john_doe'

// Mengambil objek dengan tipe
const user = await Session.get<{ id: number, name: string, role: string }>('user');
console.log(user?.role); // 'admin'

// Contoh penggunaan dengan async/await
async function getUserData() {
  const userData = await Session.get('user');
  if (userData) {
    return `Selamat datang, ${userData.name}!`;
  } else {
    return 'Silakan login terlebih dahulu';
  }
}
```

### Menghapus Data Sesi

```typescript
// Menghapus satu item
Session.remove('username');

// Menghapus semua data sesi
Session.clear();
```

### Proteksi CSRF

```typescript
// Menghasilkan token CSRF pada halaman form
async function setupForm() {
  const csrfToken = await Session.generateCSRFToken();
  document.getElementById('csrfToken').value = csrfToken;
}

// Memverifikasi token CSRF pada submit form
async function handleFormSubmit(formData) {
  const submittedToken = formData.get('csrf_token');
  const isValid = await Session.verifyCSRFToken(submittedToken);
  
  if (!isValid) {
    throw new Error('CSRF validation failed');
  }
  
  // Proses form jika validasi berhasil
  proceedWithFormSubmission(formData);
}
```

## Contoh Aplikasi Praktis

### Pengecekan Autentikasi

```typescript
async function checkAuth() {
  const user = await Session.get('user');
  
  if (!user) {
    window.location.href = '/login';
    return false;
  }
  
  return true;
}

// Gunakan pada awal setiap halaman yang memerlukan autentikasi
async function initSecurePage() {
  const isAuthenticated = await checkAuth();
  if (!isAuthenticated) return;
  
  // Lanjutkan inisialisasi halaman
  loadPageContent();
}
```

### Manajemen Login

```typescript
async function login(email, password) {
  try {
    // Asumsikan API.authenticateUser() mengembalikan data user jika berhasil
    const userData = await API.authenticateUser(email, password);
    
    if (userData) {
      await Session.set('user', userData);
      await Session.set('isLoggedIn', true);
      window.location.href = '/dashboard';
    }
  } catch (error) {
    console.error('Login failed:', error);
    return false;
  }
}

async function logout() {
  Session.remove('user');
  Session.remove('isLoggedIn');
  window.location.href = '/login';
}
```

## Detail Teknis

### Kriptografi

Session Manager menggunakan Web Crypto API untuk operasi kriptografi yang aman:

- **AES-GCM**: Algoritma enkripsi yang menyediakan confidentiality dan authentication
- **PBKDF2**: Fungsi turunan kunci yang melindungi terhadap serangan brute force
- **SHA-256**: Algoritma hash yang digunakan untuk signature dan checksum

### Implementasi Keamanan

#### Fingerprint Perangkat

Sistem membuat fingerprint unik untuk setiap perangkat berdasarkan:
- User agent
- Bahasa browser
- Kedalaman warna layar
- Resolusi layar
- Zona waktu

Fingerprint ini diverifikasi setiap kali sesi diakses untuk mendeteksi session hijacking.

#### Validasi Signature

Setiap data yang disimpan memiliki signature kriptografis untuk memastikan integritas data. Jika data dimanipulasi, signature tidak akan cocok dan sesi akan dibatalkan.

#### Protection Layers

Session Manager menerapkan beberapa lapisan perlindungan:
1. **Cookie Encryption**: Data dienkripsi sebelum disimpan
2. **Signature Validation**: Memverifikasi integritas data
3. **Checksum Verification**: Verifikasi tambahan melalui sessionStorage
4. **Fingerprint Verification**: Memvalidasi identitas perangkat
5. **Timestamp Validation**: Memvalidasi waktu sesi

## Pertimbangan Keamanan

### Keterbatasan

- **Browser Support**: Memerlukan browser yang mendukung Web Crypto API
- **Client-Side Security**: Meskipun sangat aman, solusi client-side tetap memiliki risiko yang berbeda dari solusi server-side
- **Secret Key Management**: Secret key dibuat secara acak pada setiap inisialisasi, yang berarti sesi tidak dapat dipertahankan setelah browser ditutup

### Praktik Terbaik

- Gunakan HTTPS untuk mencegah intercept saat data dikirim antara klien dan server
- Jangan simpan data sensitif dalam sesi meskipun sudah dienkripsi
- Implementasikan server-side validation untuk data yang diterima dari klien
- Tetapkan timeout sesi yang sesuai dengan kebutuhan keamanan

## Pengembangan

Session Manager dapat dikembangkan lebih lanjut dengan:

- Implementasi persistent storage untuk secret key
- Rotasi kunci secara berkala
- Dukungan untuk sinkronisasi sesi antar tab
- Integrasi dengan sistem autentikasi multi-faktor

## Lisensi

MIT License

## Kontribusi

Kontribusi sangat dihargai. Silakan buat issue atau pull request pada repository kami.

## Tentang

Session Manager dikembangkan untuk memberikan solusi keamanan tingkat tinggi untuk aplikasi web yang memerlukan perlindungan data sesi tanpa ketergantungan pada database server.
