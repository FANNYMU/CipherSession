/**
 * @class Session
 * @description Kelas untuk mengelola sesi pengguna dengan fitur keamanan tingkat lanjut.
 * Menyediakan enkripsi data, manajemen cookie, dan perlindungan terhadap berbagai serangan.
 *
 * @example
 * ```typescript
 * // Menyimpan data ke sesi
 * await Session.set('user', { id: 1, name: 'John' });
 *
 * // Mengambil data dari sesi
 * const user = await Session.get('user');
 *
 * // Menghapus data sesi
 * Session.remove('user');
 * ```
 */
class Session {
  /**
   * @private
   * @property {string} secretKey - Kunci rahasia untuk enkripsi data
   * @property {string} pepper - Nilai tambahan untuk memperkuat enkripsi
   * @property {number} iterations - Jumlah iterasi untuk algoritma PBKDF2
   * @property {number} ivLength - Panjang Initialization Vector untuk AES
   */
  private secretKey = "mySecretKey";
  private readonly pepper = "HX8q1zL7pG5aR3tY";
  private readonly iterations = 10000;
  private readonly ivLength = 16;

  /**
   * @constructor
   * @description Membuat instance baru dari Session dengan kunci rahasia yang dibuat secara acak
   */
  constructor() {
    if (typeof window !== "undefined" && window.crypto) {
      const randomBytes = new Uint8Array(32);
      window.crypto.getRandomValues(randomBytes);
      this.secretKey = Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, "0")
      ).join("");
    }
  }

  /**
   * @private
   * @method deriveKey
   * @description Menghasilkan kunci kriptografi dari password menggunakan PBKDF2
   * @param {string} password - Password yang akan diturunkan menjadi kunci
   * @param {Uint8Array} salt - Nilai salt untuk PBKDF2
   * @returns {Promise<CryptoKey>} Kunci kriptografi yang dihasilkan
   */
  private async deriveKey(
    password: string,
    salt: Uint8Array
  ): Promise<CryptoKey> {
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
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * @private
   * @method encrypt
   * @description Mengenkripsi teks menggunakan algoritma AES-GCM
   * @param {string} text - Teks yang akan dienkripsi
   * @returns {Promise<string>} Teks terenkripsi dalam format Base64
   */
  private async encrypt(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(this.ivLength));
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const key = await this.deriveKey(this.secretKey, salt);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    const result = new Uint8Array(
      salt.length + iv.length + encrypted.byteLength
    );
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encrypted), salt.length + iv.length);

    return btoa(String.fromCharCode(...result));
  }

  /**
   * @private
   * @method decrypt
   * @description Mendekripsi teks yang telah dienkripsi
   * @param {string} encryptedText - Teks terenkripsi dalam format Base64
   * @returns {Promise<string>} Teks yang telah didekripsi
   */
  private async decrypt(encryptedText: string): Promise<string> {
    try {
      const encryptedData = Uint8Array.from(atob(encryptedText), (char) =>
        char.charCodeAt(0)
      );

      const salt = encryptedData.slice(0, 16);
      const iv = encryptedData.slice(16, 16 + this.ivLength);
      const data = encryptedData.slice(16 + this.ivLength);
      const key = await this.deriveKey(this.secretKey, salt);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        data
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error("Dekripsi gagal:", error);
      return "";
    }
  }

  /**
   * @public
   * @method set
   * @description Menyimpan data ke dalam sesi dengan enkripsi
   * @param {string} key - Kunci untuk mengidentifikasi data
   * @param {any} value - Nilai yang akan disimpan
   * @param {number} days - Masa berlaku data dalam hari (default: 7)
   * @returns {Promise<void>}
   */
  async set(key: string, value: any, days = 7): Promise<void> {
    try {
      const dataWithTimestamp = {
        value,
        timestamp: Date.now(),
        fingerprint: await this.getDeviceFingerprint(),
      };

      const expires = new Date();
      expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);

      const encryptedValue = await this.encrypt(
        JSON.stringify(dataWithTimestamp)
      );

      const signature = await this.generateSignature(encryptedValue);

      document.cookie = `${key}=${encodeURIComponent(
        encryptedValue
      )}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure`;

      document.cookie = `${key}_sig=${encodeURIComponent(
        signature
      )}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure`;

      if (typeof sessionStorage !== "undefined") {
        sessionStorage.setItem(
          `${key}_checksum`,
          await this.generateChecksum(encryptedValue)
        );
      }
    } catch (error) {
      console.error("Gagal menyimpan session:", error);
    }
  }

  /**
   * @public
   * @method get
   * @description Mengambil data dari sesi dan memverifikasi keamanannya
   * @template T - Tipe data yang diharapkan
   * @param {string} key - Kunci untuk mengambil data
   * @returns {Promise<T | null>} Data yang diminta atau null jika tidak ditemukan/invalid
   */
  async get<T = any>(key: string): Promise<T | null> {
    try {
      const cookies = document.cookie.split("; ");
      let encryptedValue = null;
      let signature = null;

      for (const cookie of cookies) {
        const [cookieKey, cookieValue] = cookie.split("=");
        if (cookieKey === key && cookieValue) {
          encryptedValue = decodeURIComponent(cookieValue);
        } else if (cookieKey === `${key}_sig` && cookieValue) {
          signature = decodeURIComponent(cookieValue);
        }
      }

      if (!encryptedValue || !signature) {
        return null;
      }

      const isValid = await this.verifySignature(encryptedValue, signature);
      if (!isValid) {
        console.error("Session telah dimanipulasi!");
        this.remove(key);
        return null;
      }

      if (typeof sessionStorage !== "undefined") {
        const storedChecksum = sessionStorage.getItem(`${key}_checksum`);
        const currentChecksum = await this.generateChecksum(encryptedValue);

        if (storedChecksum !== currentChecksum) {
          console.error("Checksum tidak cocok!");
          this.remove(key);
          return null;
        }
      }

      const decrypted = await this.decrypt(encryptedValue);
      if (!decrypted) return null;

      const data = JSON.parse(decrypted);

      const currentFingerprint = await this.getDeviceFingerprint();
      if (data.fingerprint !== currentFingerprint) {
        console.error("Fingerprint tidak cocok!");
        this.remove(key);
        return null;
      }

      const sessionAge = Date.now() - data.timestamp;
      if (sessionAge > 12 * 60 * 60 * 1000) {
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

  /**
   * @public
   * @method remove
   * @description Menghapus data sesi berdasarkan kunci
   * @param {string} key - Kunci data yang akan dihapus
   */
  remove(key: string): void {
    document.cookie = `${key}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict; Secure`;
    document.cookie = `${key}_sig=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict; Secure`;

    if (typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem(`${key}_checksum`);
    }
  }

  /**
   * @public
   * @method clear
   * @description Menghapus semua data sesi
   */
  clear(): void {
    document.cookie.split("; ").forEach((cookie) => {
      const [cookieKey] = cookie.split("=");
      this.remove(cookieKey);
    });

    if (typeof sessionStorage !== "undefined") {
      sessionStorage.clear();
    }
  }

  /**
   * @private
   * @method getDeviceFingerprint
   * @description Menghasilkan fingerprint unik untuk perangkat
   * @returns {Promise<string>} Fingerprint dalam format hex
   */
  private async getDeviceFingerprint(): Promise<string> {
    const components = [
      navigator.userAgent,
      navigator.language,
      screen.colorDepth,
      screen.width + "x" + screen.height,
      new Date().getTimezoneOffset(),
    ];

    const encoder = new TextEncoder();
    const data = encoder.encode(components.join("||"));
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * @private
   * @method generateSignature
   * @description Membuat tanda tangan digital untuk data
   * @param {string} data - Data yang akan ditandatangani
   * @returns {Promise<string>} Tanda tangan dalam format hex
   */
  private async generateSignature(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data + this.secretKey);
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * @private
   * @method verifySignature
   * @description Memverifikasi tanda tangan digital
   * @param {string} data - Data yang akan diverifikasi
   * @param {string} signature - Tanda tangan yang akan dicocokkan
   * @returns {Promise<boolean>} Hasil verifikasi
   */
  private async verifySignature(
    data: string,
    signature: string
  ): Promise<boolean> {
    const calculatedSignature = await this.generateSignature(data);
    return calculatedSignature === signature;
  }

  /**
   * @private
   * @method generateChecksum
   * @description Menghasilkan checksum untuk data
   * @param {string} data - Data yang akan dihitung checksumnya
   * @returns {Promise<string>} Checksum dalam format hex
   */
  private async generateChecksum(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data + this.pepper);
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * @public
   * @method verifyCSRFToken
   * @description Memverifikasi token CSRF
   * @param {string} token - Token yang akan diverifikasi
   * @returns {Promise<boolean>} Hasil verifikasi
   */
  public async verifyCSRFToken(token: string): Promise<boolean> {
    const storedToken = await this.get<string>("csrf_token");
    return storedToken === token;
  }

  /**
   * @public
   * @method generateCSRFToken
   * @description Menghasilkan token CSRF baru
   * @returns {Promise<string>} Token CSRF yang dihasilkan
   */
  public async generateCSRFToken(): Promise<string> {
    const tokenArray = new Uint8Array(32);
    window.crypto.getRandomValues(tokenArray);
    const token = Array.from(tokenArray, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
    await this.set("csrf_token", token);
    return token;
  }
}

export default new Session();
