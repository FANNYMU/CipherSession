class Session {
    private secretKey = "mySecretKey"; // ganti dengan secret key yang kuat dan acak
    private readonly pepper = "HX8q1zL7pG5aR3tY"; // nilai tetap tambahan untuk memperkuat enkripsi
    private readonly iterations = 10000; // jumlah iterasi untuk PBKDF2
    private readonly ivLength = 16; // panjang IV untuk AES

    constructor() {
        // Gunakan secure random generator untuk membuat secretKey yang kuat
        if (typeof window !== 'undefined' && window.crypto) {
            const randomBytes = new Uint8Array(32);
            window.crypto.getRandomValues(randomBytes);
            this.secretKey = Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
        }
    }

    // Fungsi untuk menghasilkan kunci dari password menggunakan PBKDF2
    private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const encoder = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(password + this.pepper),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: this.iterations,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    // Mengenkripsi data menggunakan AES-GCM
    private async encrypt(text: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        // Buat IV (Initialization Vector) acak
        const iv = window.crypto.getRandomValues(new Uint8Array(this.ivLength));

        // Buat salt acak untuk PBKDF2
        const salt = window.crypto.getRandomValues(new Uint8Array(16));

        // Dapatkan kunci enkripsi
        const key = await this.deriveKey(this.secretKey, salt);

        // Enkripsi data
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );

        // Gabungkan salt, iv, dan data terenkripsi ke dalam satu buffer
        const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(new Uint8Array(encrypted), salt.length + iv.length);

        // Konversi ke string Base64
        return btoa(String.fromCharCode(...result));
    }

    // Mendekripsi data yang dienkripsi dengan AES-GCM
    private async decrypt(encryptedText: string): Promise<string> {
        try {
            // Konversi dari Base64 ke array
            const encryptedData = Uint8Array.from(atob(encryptedText), char => char.charCodeAt(0));

            // Ekstrak salt, iv, dan data terenkripsi
            const salt = encryptedData.slice(0, 16);
            const iv = encryptedData.slice(16, 16 + this.ivLength);
            const data = encryptedData.slice(16 + this.ivLength);

            // Dapatkan kunci dekripsi
            const key = await this.deriveKey(this.secretKey, salt);

            // Dekripsi data
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                data
            );

            // Konversi ke string
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            console.error("Dekripsi gagal:", error);
            return "";
        }
    }

    async set(key: string, value: any, days = 7): Promise<void> {
        try {
            // Tambahkan timestamp untuk menandai waktu pembuatan
            const dataWithTimestamp = {
                value,
                timestamp: Date.now(),
                fingerprint: await this.getDeviceFingerprint()
            };

            const expires = new Date();
            expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);

            // Enkripsi data
            const encryptedValue = await this.encrypt(JSON.stringify(dataWithTimestamp));

            // Tambahkan signature untuk mendeteksi manipulasi
            const signature = await this.generateSignature(encryptedValue);

            // Set cookie dengan flag HttpOnly dan Secure
            document.cookie = `${key}=${encodeURIComponent(encryptedValue)}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure`;

            // Simpan signature di cookie terpisah
            document.cookie = `${key}_sig=${encodeURIComponent(signature)}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure`;

            // Tambahkan perlindungan tambahan dengan storage anti-tampering
            if (typeof sessionStorage !== 'undefined') {
                sessionStorage.setItem(`${key}_checksum`, await this.generateChecksum(encryptedValue));
            }
        } catch (error) {
            console.error("Gagal menyimpan session:", error);
        }
    }

    async get<T = any>(key: string): Promise<T | null> {
        try {
            // Cari cookie berdasarkan key
            const cookies = document.cookie.split("; ");
            let encryptedValue = null;
            let signature = null;

            for (const cookie of cookies) {
                const [cookieKey, cookieValue] = cookie.split("=");
                if (cookieKey === key) {
                    encryptedValue = decodeURIComponent(cookieValue);
                } else if (cookieKey === `${key}_sig`) {
                    signature = decodeURIComponent(cookieValue);
                }
            }

            if (!encryptedValue || !signature) {
                return null;
            }

            // Verifikasi signature untuk mencegah manipulasi
            const isValid = await this.verifySignature(encryptedValue, signature);
            if (!isValid) {
                console.error("Session telah dimanipulasi!");
                this.remove(key);
                return null;
            }

            // Verifikasi checksum tambahan
            if (typeof sessionStorage !== 'undefined') {
                const storedChecksum = sessionStorage.getItem(`${key}_checksum`);
                const currentChecksum = await this.generateChecksum(encryptedValue);

                if (storedChecksum !== currentChecksum) {
                    console.error("Checksum tidak cocok!");
                    this.remove(key);
                    return null;
                }
            }

            // Dekripsi data
            const decrypted = await this.decrypt(encryptedValue);
            if (!decrypted) return null;

            const data = JSON.parse(decrypted);

            // Verifikasi fingerprint untuk mencegah session hijacking
            const currentFingerprint = await this.getDeviceFingerprint();
            if (data.fingerprint !== currentFingerprint) {
                console.error("Fingerprint tidak cocok!");
                this.remove(key);
                return null;
            }

            // Verifikasi masa berlaku berbasis waktu
            const sessionAge = Date.now() - data.timestamp;
            if (sessionAge > 12 * 60 * 60 * 1000) { // 12 jam
                console.warn("Session terlalu lama tidak aktif");
                this.remove(key);
                return null;
            }

            return data.value as T;
        } catch (error) {
            console.error("Gagal mengambil session:", error);
            return null;
        }
    }

    remove(key: string): void {
        document.cookie = `${key}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict; Secure`;
        document.cookie = `${key}_sig=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict; Secure`;

        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.removeItem(`${key}_checksum`);
        }
    }

    clear(): void {
        document.cookie.split("; ").forEach(cookie => {
            const [cookieKey] = cookie.split("=");
            this.remove(cookieKey);
        });

        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.clear();
        }
    }

    // Membuat fingerprint perangkat berdasarkan beberapa parameter
    private async getDeviceFingerprint(): Promise<string> {
        const components = [
            navigator.userAgent,
            navigator.language,
            screen.colorDepth,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset()
        ];

        // Hashing komponen untuk membuat fingerprint
        const encoder = new TextEncoder();
        const data = encoder.encode(components.join('||'));
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Fungsi untuk membuat signature
    private async generateSignature(data: string): Promise<string> {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data + this.secretKey);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Fungsi untuk memverifikasi signature
    private async verifySignature(data: string, signature: string): Promise<boolean> {
        const calculatedSignature = await this.generateSignature(data);
        return calculatedSignature === signature;
    }

    // Fungsi untuk menghasilkan checksum
    private async generateChecksum(data: string): Promise<string> {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data + this.pepper);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Fungsi untuk memeriksa CSRF token
    public async verifyCSRFToken(token: string): Promise<boolean> {
        const storedToken = await this.get<string>('csrf_token');
        return storedToken === token;
    }

    // Fungsi untuk menghasilkan CSRF token
    public async generateCSRFToken(): Promise<string> {
        const tokenArray = new Uint8Array(32);
        window.crypto.getRandomValues(tokenArray);
        const token = Array.from(tokenArray, byte => byte.toString(16).padStart(2, '0')).join('');
        await this.set('csrf_token', token);
        return token;
    }
}

export default new Session();