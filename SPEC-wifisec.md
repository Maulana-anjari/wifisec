# SPEC — wifisec

Spesifikasi implementasi untuk dieksekusi oleh AI coding agent.

| | |
|---|---|
| Versi spec | 1.0 |
| Tanggal | 16 Agustus 2026 |
| Bahasa | Go 1.22+ |
| TUI | bubbletea + lipgloss |
| Target v1.0 | Linux, macOS |
| Dokumen terkait | PRD-wifisec.md |

---

## 0. Cara membaca dokumen ini

Dokumen ini adalah spesifikasi yang mengikat. Agent yang mengerjakan harus mematuhi hal berikut:

1. **Jangan mengubah nama tipe, field JSON, atau ID check** yang didefinisikan di sini. Kode lain bergantung padanya.
2. **Tulis test sebelum implementasi** untuk setiap komponen di Bagian 8. Test adalah bagian yang akan direview manusia.
3. **Gaya kode: eksplisit dan membosankan.** Fungsi pendek, tanpa abstraksi spekulatif, error ditangani di tempat kejadian. Hindari generics kecuali benar-benar mengurangi duplikasi. Hindari refleksi sepenuhnya.
4. **Jangan menambahkan check di luar Bagian 6** tanpa persetujuan eksplisit. Registry adalah scope yang mengikat.
5. **Jangan menambahkan dependensi** di luar Bagian 3.3 tanpa persetujuan eksplisit.
6. Jika spesifikasi ini ambigu atau kontradiktif di suatu titik, **berhenti dan tanyakan**, jangan menebak.

### 0.1 Larangan absolut

Fitur berikut tidak boleh diimplementasikan dalam bentuk apa pun, termasuk sebagai utilitas internal, kode yang dikomentari, atau eksperimen di branch:

- Mekanisme apa pun untuk melewati, menghindari, atau menyamarkan diri dari blokir jaringan
- Discovery atau enumerasi perangkat lain di jaringan (ARP scan, mDNS/NetBIOS sweep, ping sweep)
- Pengujian keamanan terhadap perangkat atau layanan milik pihak lain
- Pengiriman paket dengan header yang dipalsukan
- Penyimpanan atau transmisi kredensial jaringan

Jika sebuah kebutuhan tampak memerlukan salah satu di atas, itu berarti kebutuhan tersebut salah dipahami. Berhenti dan tanyakan.

---

## 1. Tujuan

`wifisec` menjawab satu pertanyaan: **apakah jaringan WiFi ini aman untuk dipakai?**

Asumsi desain utama: **pengguna adalah tamu di jaringan yang ia periksa.** Karena itu mode default tidak mengirim satu paket pun, dan setiap peningkatan level pemeriksaan memerlukan konfirmasi eksplisit.

Tiga pertanyaan operasional yang harus terjawab di profil `passive` dan `minimal`:

1. Apakah trafik HTTPS saya dapat dibaca oleh operator jaringan?
2. Apakah DNS saya dimanipulasi atau diawasi?
3. Apakah jaringan ini memblokir hal yang saya butuhkan?

---

## 2. Prinsip yang mengikat implementasi

**P1 — Aman secara default.** Profil `passive` adalah default pada setiap start proses, mengabaikan state sebelumnya.

**P2 — Observasi terpisah dari kesimpulan.** Tipe `Check` tidak boleh mengandung field penilaian seperti "blocked" atau "dangerous". Penilaian hanya ada di `Finding` dan `Verdict`.

**P3 — `inconclusive` adalah status kelas satu.** Kegagalan tanpa kontrol pembanding wajib menghasilkan `StatusInconclusive`, bukan kesimpulan negatif.

**P4 — Blind spot wajib dilaporkan.** Verdict yang tidak mencantumkan apa yang tidak diperiksa dianggap bug.

**P5 — Klaim harus dapat diverifikasi.** Setiap klaim perilaku di dokumen ini harus punya test yang membuktikannya. Klaim "profil pasif tidak mengirim paket" diverifikasi oleh T1 di Bagian 8.

---

## 3. Arsitektur

### 3.1 Struktur direktori

```
wifisec/
├── cmd/wifisec/
│   └── main.go                  entrypoint, parsing flag
├── internal/
│   ├── model/                   tipe data, tanpa dependensi internal lain
│   │   ├── check.go
│   │   ├── finding.go
│   │   ├── verdict.go
│   │   ├── profile.go
│   │   └── result.go
│   ├── registry/                definisi check deklaratif
│   │   ├── registry.go
│   │   └── checks.yaml
│   ├── checks/                  implementasi check
│   │   ├── runner.go            orkestrasi, concurrency, streaming
│   │   ├── local/               check nol-paket
│   │   ├── dns/
│   │   ├── tls/
│   │   └── net/
│   ├── platform/                adapter OS
│   │   ├── platform.go          interface
│   │   ├── linux.go             build tag linux
│   │   ├── darwin.go            build tag darwin
│   │   └── stub.go              build tag !linux,!darwin
│   ├── interpret/               checks → findings → verdict
│   │   ├── rules.go
│   │   └── rules.yaml
│   ├── guard/                   penegakan profil
│   │   ├── profile.go
│   │   └── counter.go           penghitung paket global
│   ├── tui/                     bubbletea
│   │   ├── app.go
│   │   ├── screen_verdict.go
│   │   ├── screen_findings.go
│   │   ├── screen_detail.go
│   │   ├── screen_live.go
│   │   ├── dialog_profile.go
│   │   └── style.go
│   └── output/
│       ├── json.go
│       └── report.go
├── testdata/
│   └── fixtures/                JSON hasil untuk uji renderer
└── docs/
```

**Aturan dependensi:** `model` tidak boleh mengimpor paket internal lain. `tui` hanya boleh mengimpor `model`. `checks` tidak boleh mengimpor `tui`. Pelanggaran aturan ini adalah bug arsitektural.

### 3.2 Alur eksekusi

```
main
  └─ parse flag, tentukan profil (default: passive)
     └─ guard.Enforce(profil, jaringan)     ← bisa menolak atau menurunkan
        └─ registry.Filter(profil)          ← check di luar profil → skipped
           └─ runner.Run(ctx, checks)       ← paralel, hasil ke channel
              └─ tui menerima streaming     ← render bertahap
                 └─ interpret.Apply(checks) ← findings + verdict
                    └─ render verdict akhir
```

### 3.3 Dependensi yang diizinkan

| Paket | Kegunaan |
|---|---|
| `github.com/charmbracelet/bubbletea` | TUI |
| `github.com/charmbracelet/lipgloss` | styling TUI |
| `github.com/miekg/dns` | kontrol query DNS presisi |
| `gopkg.in/yaml.v3` | registry dan rules |
| `github.com/spf13/pflag` | parsing flag |

Selain itu gunakan standard library. Khususnya: `crypto/tls`, `net`, `net/http`, `context`, `encoding/json`.

**Jangan tambahkan:** library ICMP pihak ketiga, framework DI, library logging struktural, ORM apa pun.

---

## 4. Tipe data

Definisi berikut mengikat. Nama field JSON tidak boleh berubah setelah rilis.

### 4.1 Profil

```go
package model

type Profile string

const (
    ProfilePassive  Profile = "passive"
    ProfileMinimal  Profile = "minimal"
    ProfileStandard Profile = "standard"
    ProfileFull     Profile = "full"
)

// Level mengembalikan urutan numerik untuk perbandingan.
// passive=0, minimal=1, standard=2, full=3
func (p Profile) Level() int

// EstimatedPackets untuk ditampilkan di dialog konfirmasi.
func (p Profile) EstimatedPackets() int

// Allows melaporkan apakah profil ini mengizinkan check
// yang membutuhkan profil minimum tertentu.
func (p Profile) Allows(required Profile) bool
```

### 4.2 Check

```go
type CheckStatus string

const (
    StatusNormal       CheckStatus = "normal"
    StatusAnomalous    CheckStatus = "anomalous"
    StatusInconclusive CheckStatus = "inconclusive"
    StatusSkipped      CheckStatus = "skipped"
    StatusError        CheckStatus = "error"
)

type Confidence string

const (
    ConfidenceHigh   Confidence = "high"
    ConfidenceMedium Confidence = "medium"
    ConfidenceLow    Confidence = "low"
)

type Layer string

const (
    LayerLocal Layer = "local"
    LayerWiFi  Layer = "wifi"
    LayerDNS   Layer = "dns"
    LayerL4    Layer = "l4"
    LayerTLS   Layer = "tls"
    LayerHTTP  Layer = "http"
    LayerPerf  Layer = "perf"
)

type Control struct {
    Performed bool   `json:"performed"`
    Reason    string `json:"reason,omitempty"`
    Result    string `json:"result,omitempty"`
}

type Check struct {
    ID              string            `json:"id"`
    Layer           Layer             `json:"layer"`
    Title           string            `json:"title"`
    ProfileRequired Profile           `json:"profile_required"`
    Status          CheckStatus       `json:"status"`
    Confidence      Confidence        `json:"confidence"`
    Target          string            `json:"target,omitempty"`
    Observed        map[string]any    `json:"observed,omitempty"`
    Expected        map[string]any    `json:"expected,omitempty"`
    Control         Control           `json:"control"`
    PacketsSent     int               `json:"packets_sent"`
    DurationMS      int64             `json:"duration_ms"`
    Error           string            `json:"error,omitempty"`
}
```

**Aturan validasi Check** (ditegakkan di `model.ValidateCheck`):

- `Status == StatusSkipped` mensyaratkan `PacketsSent == 0`
- `Status == StatusAnomalous` dengan `Control.Performed == false` mensyaratkan `Confidence != ConfidenceHigh`, kecuali check tersebut ditandai `self_evident` di registry
- `Observed` tidak boleh berisi kunci yang mengandung penilaian (`blocked`, `dangerous`, `unsafe`). Ini penegakan P2.

### 4.3 Finding

```go
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityWarning  Severity = "warning"
    SeverityInfo     Severity = "info"
)

type Finding struct {
    ID                 string     `json:"id"`
    Severity           Severity   `json:"severity"`
    Confidence         Confidence `json:"confidence"`
    Title              string     `json:"title"`
    Explanation        string     `json:"explanation"`
    Impact             []string   `json:"impact,omitempty"`
    BasedOn            []string   `json:"based_on"`
    Recommendation     string     `json:"recommendation"`
    FalsePositiveHints []string   `json:"false_positive_hints,omitempty"`
}
```

`BasedOn` wajib berisi minimal satu ID check yang ada di hasil. Finding tanpa `BasedOn` valid dianggap bug.

### 4.4 Verdict

```go
type Safety string

const (
    SafetyOK       Safety = "ok"
    SafetyCaution  Safety = "caution"
    SafetyAvoid    Safety = "avoid"
    SafetyUnknown  Safety = "unknown"
)

type Verdict struct {
    Safety      Safety            `json:"safety"`
    Score       int               `json:"score"`
    Headline    string            `json:"headline"`
    TopFindings []string          `json:"top_findings"`
    BlindSpots  []string          `json:"blind_spots"`
    UseCases    map[string]string `json:"use_cases"`
}
```

`BlindSpots` wajib terisi jika ada check berstatus `skipped`. Verdict dengan skipped check tapi `BlindSpots` kosong dianggap bug (penegakan P4).

### 4.5 Envelope hasil

```go
type NetworkInfo struct {
    SSIDHash     string `json:"ssid_hash"`
    BSSIDHash    string `json:"bssid_hash"`
    OUI          string `json:"oui,omitempty"`
    Band         string `json:"band,omitempty"`
    Channel      int    `json:"channel,omitempty"`
    Security     string `json:"security,omitempty"`
    PMF          string `json:"pmf,omitempty"`
    KnownNetwork bool   `json:"known_network"`

    ssidPlain  string
    bssidPlain string
}

type Result struct {
    SchemaVersion string      `json:"schema_version"`
    ToolVersion   string      `json:"tool_version"`
    RunID         string      `json:"run_id"`
    StartedAt     time.Time   `json:"started_at"`
    DurationMS    int64       `json:"duration_ms"`
    Profile       Profile     `json:"profile"`
    Network       NetworkInfo `json:"network"`
    Checks        []Check     `json:"checks"`
    Findings      []Finding   `json:"findings"`
    Verdict       Verdict     `json:"verdict"`
}
```

`SchemaVersion` untuk v1.0 adalah `"1.0"`.

Field `ssidPlain` dan `bssidPlain` tidak diekspor sehingga tidak pernah masuk ke JSON. Nilai plaintext hanya dipakai untuk tampilan TUI dan pencocokan whitelist. Hash memakai SHA-256 dengan prefix `sha256:`.

### 4.6 Interface check

```go
type CheckContext struct {
    Platform      platform.Adapter
    Counter       *guard.PacketCounter
    ControlServer *ControlServerConfig  // nil jika tidak dikonfigurasi
    Timeout       time.Duration
}

type Checker interface {
    // Definition mengembalikan metadata statis.
    Definition() CheckDefinition

    // Run menjalankan pemeriksaan. Wajib menghormati pembatalan ctx.
    // Wajib melaporkan setiap paket terkirim melalui cc.Counter.
    Run(ctx context.Context, cc CheckContext) Check
}

type CheckDefinition struct {
    ID                    string
    Layer                 Layer
    Title                 string
    Description           string
    ProfileRequired       Profile
    RequiresControlServer bool
    RequiresPrivilege     bool
    SelfEvident           bool
    EstimatedPackets      int
}
```

### 4.7 Adapter platform

```go
package platform

type WiFiInfo struct {
    SSID      string
    BSSID     string
    RSSI      int
    Channel   int
    Band      string
    Security  string
    PMF       string
    LinkSpeed int
    Available bool
    Reason    string  // jika Available == false
}

type NetConfig struct {
    Interface  string
    IP         string
    Gateway    string
    Netmask    string
    MTU        int
    DNSServers []string
}

type ProxyConfig struct {
    Enabled  bool
    HTTPProxy  string
    HTTPSProxy string
    PACUrl     string
}

type Adapter interface {
    WiFiInfo() (WiFiInfo, error)
    NetConfig() (NetConfig, error)
    ProxyConfig() (ProxyConfig, error)
    TrustStoreCAs() ([]CACert, error)
    RoutingTable() ([]Route, error)
}

func New() Adapter  // memilih implementasi berdasarkan build tag
```

**Catatan implementasi platform:** semua metode di atas wajib nol paket jaringan. Implementasi boleh shell-out ke utilitas OS (`iw`, `nmcli`, `wdutil`, `networksetup`, `security`) dan mem-parse outputnya. Shell-out lebih disukai daripada cgo karena mempertahankan cross-compilation dan lebih mudah di-mock.

Jika utilitas tidak tersedia atau parsing gagal, kembalikan `WiFiInfo{Available: false, Reason: "..."}` — **jangan** kembalikan error yang menggagalkan seluruh run.

Untuk macOS: verifikasi terlebih dahulu perilaku aktual di versi target, karena cara memperoleh BSSID berubah di beberapa rilis terakhir dan sebagian field kini memerlukan izin lokasi. Jika BSSID tidak dapat diperoleh tanpa izin tambahan, laporkan sebagai `Available: false` dengan alasan jelas, dan pastikan whitelist jaringan tetap berfungsi berbasis SSID sebagai fallback.

---

## 5. Sistem profil dan guard rail

Ini komponen paling kritis. Implementasikan sebelum check aktif apa pun ada.

### 5.1 Penghitung paket

```go
package guard

type PacketCounter struct {
    mu      sync.Mutex
    total   int
    byCheck map[string]int
    limit   int   // dari profil aktif
}

// Add mencatat paket terkirim. Mengembalikan error jika
// melewati batas profil aktif.
func (c *PacketCounter) Add(checkID string, n int) error

func (c *PacketCounter) Total() int
```

Setiap check yang mengirim paket **wajib** memanggil `Add` sebelum mengirim. Pada profil `passive`, `limit` adalah 0, sehingga panggilan `Add` apa pun mengembalikan error dan check gagal dengan `StatusError`.

Ini pengaman lapis kedua. Lapis pertama adalah penyaringan registry berdasarkan profil.

### 5.2 Aturan penegakan profil

Implementasikan di `guard.Enforce`:

| Aturan | Perilaku |
|---|---|
| G1 | Profil default `passive` pada setiap start proses. State sesi sebelumnya tidak dibaca. |
| G2 | Menaikkan profil di atas `passive` memerlukan konfirmasi mengetik nama profil secara lengkap dan persis. |
| G3 | Dialog konfirmasi menampilkan estimasi paket, status `KnownNetwork`, dan peringatan spesifik untuk `full`. |
| G4 | Perubahan BSSID saat runtime menurunkan profil ke `passive` seketika dan membatalkan check yang sedang berjalan. |
| G5 | Profil `full` pada jaringan dengan `KnownNetwork == false` memerlukan konfirmasi kedua. |
| G6 | Flag `--profile` di CLI tetap tunduk pada G4 dan G5. Untuk profil di atas `standard`, `--profile` memerlukan `--i-own-this-network` sebagai konfirmasi non-interaktif. |
| G7 | Whitelist disimpan di `$XDG_CONFIG_HOME/wifisec/known_networks.yaml` berisi hash BSSID. Hanya jaringan di daftar ini yang berstatus `KnownNetwork`. |

### 5.3 Perilaku yang dilarang

- Menyimpan profil terakhir dan memulihkannya di sesi berikutnya
- Flag apa pun yang melewati konfirmasi untuk profil `full` selain `--i-own-this-network`
- Menjalankan check dengan `ProfileRequired` di atas profil aktif, dalam kondisi apa pun

---

## 6. Registry check v1.0

Definisi disimpan di `internal/registry/checks.yaml` dan dimuat saat start. Perintah `wifisec list-checks` menampilkan seluruh isi registry tanpa menjalankan apa pun.

### 6.1 Profil passive — 0 paket

| ID | Layer | Judul | Mengamati |
|---|---|---|---|
| `local.interface` | local | Konfigurasi interface | IP, netmask, MTU, nama interface |
| `local.gateway` | local | Gateway default | IP gateway, apakah privat |
| `local.dns_servers` | local | Server DNS dari DHCP | daftar resolver, klasifikasi internal/publik |
| `local.routing` | local | Tabel routing | rute default, rute mencurigakan |
| `local.mtu` | local | MTU interface | nilai MTU, apakah non-standar |
| `local.proxy_system` | local | Proxy sistem | HTTP/HTTPS proxy, PAC URL |
| `local.trust_store` | local | CA di trust store | CA non-publik yang terpasang |
| `wifi.security` | wifi | Tipe enkripsi | WPA2/WPA3/WEP/open |
| `wifi.pmf` | wifi | Protected Management Frames | enabled/disabled/required |
| `wifi.signal` | wifi | Kekuatan sinyal | RSSI, estimasi kualitas |
| `wifi.channel` | wifi | Channel dan band | channel, band, lebar |
| `wifi.bssid_vendor` | wifi | Vendor perangkat AP | OUI, nama vendor |
| `wifi.link_speed` | wifi | Kecepatan link negosiasi | Mbps |

**Catatan khusus `local.trust_store`:** tandai `self_evident: true` di registry. Check ini boleh berstatus `anomalous` dengan `Confidence: high` tanpa kontrol, karena keberadaan CA non-publik di trust store adalah fakta lokal yang tidak memerlukan pembanding.

Klasifikasi CA "non-publik" dilakukan dengan membandingkan terhadap daftar CA publik yang dibundel dalam binary. CA yang tidak ada di daftar tersebut dilaporkan apa adanya beserta subject dan issuer — **jangan** menyimpulkan niat jahat, karena CA perusahaan pada perangkat ber-MDM adalah kondisi sah dan umum.

### 6.2 Profil minimal — ~2 paket

| ID | Layer | Judul | Mengamati | Paket |
|---|---|---|---|---|
| `dns.resolve_basic` | dns | Resolusi DNS dasar | hasil resolve satu domain kontrol | 1 |
| `tls.cert_issuer` | tls | Penerbit sertifikat | issuer, fingerprint, panjang rantai | 1 |

`tls.cert_issuer` wajib memakai `InsecureSkipVerify: true` dengan `VerifyPeerCertificate` custom untuk memperoleh sertifikat mentah tanpa validasi. Sertifikat **tidak boleh** ditolak — tujuannya justru memeriksa apa yang diberikan jaringan.

Target default: satu domain besar yang stabil. Simpan fingerprint baseline yang dibundel dalam binary, dan tandai `Expected.source` sebagai `baseline_bundled`. Jika fingerprint tidak cocok, ini `anomalous` — tapi karena rotasi sertifikat normal terjadi, `Confidence` maksimal `medium` kecuali issuer juga ditemukan di trust store lokal.

### 6.3 Profil standard

| ID | Layer | Judul | Paket |
|---|---|---|---|
| `net.captive_portal` | http | Deteksi captive portal | ~2 |
| `net.latency_gateway` | perf | Latency ke gateway | ~10 |
| `net.latency_internet` | perf | Latency ke internet | ~10 |
| `net.jitter` | perf | Jitter | dari latency |
| `net.packet_loss` | perf | Packet loss | dari latency |
| `dns.compare_doh` | dns | Perbandingan DNS jaringan vs DoH | ~4 |
| `dns.transparent_proxy` | dns | Deteksi intersepsi port 53 | ~2 |
| `net.bufferbloat` | perf | Latency saat dibebani | ~20 |
| `net.ipv6` | l4 | Ketersediaan IPv6 | ~2 |

**Urutan wajib:** `net.captive_portal` harus berjalan dan selesai sebelum check lain di profil ini. Captive portal yang belum login adalah penyebab false positive terbesar. Jika portal terdeteksi, seluruh check lain berstatus `inconclusive` dengan alasan `captive_portal_detected`.

### 6.4 Profil full

| ID | Layer | Judul | Butuh kontrol |
|---|---|---|---|
| `l4.port_reachability` | l4 | Ketercapaian port umum | ya |
| `tls.sni_inspection` | tls | Deteksi inspeksi SNI | ya |
| `tls.ech_support` | tls | Dukungan ECH | ya |
| `http.header_injection` | http | Header yang disisipkan proxy | tidak |
| `net.path_mtu` | l4 | Path MTU discovery | ya |
| `net.throttling` | perf | Throttling selektif | ya |
| `net.quic` | l4 | Ketersediaan QUIC/HTTP3 | tidak |
| `wifi.channel_congestion` | wifi | Kongesti channel | tidak |

Check dengan `RequiresControlServer: true` berstatus `skipped` jika control server tidak dikonfigurasi, dengan alasan `no_control_server`, dan wajib muncul di `BlindSpots`.

**`l4.port_reachability` memerlukan pengaman tambahan:** beri jeda minimal 200ms antar koneksi dan batasi ke maksimal 20 port. Tujuannya menghindari pola yang menyerupai port scan. Jangan menjalankan koneksi paralel di check ini.

---

## 7. Interpretasi

### 7.1 Struktur aturan

Aturan disimpan di `internal/interpret/rules.yaml`, bukan di kode Go. Format:

```yaml
- id: tls_interception
  severity: critical
  when:
    all:
      - check: tls.cert_issuer
        status: anomalous
      - check: local.trust_store
        observed:
          non_public_ca_found: true
  confidence: high
  title: "Trafik HTTPS kemungkinan besar dibaca oleh operator jaringan"
  explanation: |
    Sertifikat diterbitkan oleh CA yang tidak dikenal publik dan CA
    tersebut terpasang di trust store perangkat ini. Artinya isi
    koneksi HTTPS dapat didekripsi di jaringan.
  impact: [password, email, chat, internal_docs]
  recommendation: |
    Hindari login ke akun pribadi. Gunakan koneksi seluler untuk
    hal sensitif.
  false_positive_hints:
    - "Umum dan sah pada perangkat milik perusahaan dengan MDM."
```

Evaluator mendukung `all`, `any`, dan `not`. Tidak perlu lebih dari itu — jika sebuah aturan butuh logika lebih kompleks, aturannya yang salah.

### 7.2 Aturan minimum v1.0

Implementasikan minimal finding berikut:

| ID finding | Severity | Sumber utama |
|---|---|---|
| `tls_interception` | critical | `tls.cert_issuer` + `local.trust_store` |
| `foreign_ca_present` | warning | `local.trust_store` |
| `weak_encryption` | critical | `wifi.security` (WEP/open) |
| `no_pmf` | warning | `wifi.pmf` |
| `dns_internal_resolver` | warning | `local.dns_servers` |
| `dns_manipulation` | critical | `dns.compare_doh` |
| `transparent_dns_proxy` | warning | `dns.transparent_proxy` |
| `system_proxy_forced` | warning | `local.proxy_system` |
| `captive_portal` | info | `net.captive_portal` |
| `poor_quality` | info | `net.jitter` + `net.packet_loss` |
| `bufferbloat` | info | `net.bufferbloat` |

### 7.3 Perhitungan verdict

```
score = 100
  − 40 jika ada finding critical
  − 15 per finding warning (maks −45)
  − 5 per finding info (maks −15)

safety:
  score ≥ 80 dan tanpa critical  → ok
  score ≥ 50 dan tanpa critical  → caution
  ada critical                   → avoid
  seluruh check gagal/skipped    → unknown
```

`BlindSpots` diisi otomatis dari check berstatus `skipped`, dikelompokkan berdasarkan kategori yang dapat dibaca manusia, bukan daftar ID mentah.

`UseCases` untuk v1.0 berisi kunci: `browsing_umum`, `login_akun_pribadi`, `kerja_sensitif`, `internet_banking`. Nilai: `ok`, `caution`, `avoid`.

---

## 8. Strategi testing

Test adalah bagian yang akan direview manusia. Tulis test lebih dulu, dan buat namanya deskriptif.

### 8.1 Test wajib

**T1 — Profil pasif tidak mengirim paket.** Jalankan seluruh check profil `passive` dan assert `counter.Total() == 0`. Di CI Linux, jalankan tambahan di dalam network namespace tanpa route default; seluruh check harus tetap selesai tanpa error jaringan. Ini test terpenting di seluruh proyek.

**T2 — Registry menghormati profil.** Untuk setiap profil, assert bahwa `registry.Filter(p)` tidak mengembalikan check dengan `ProfileRequired.Level() > p.Level()`.

**T3 — Penghitung paket menolak melewati batas.** Assert `counter.Add` mengembalikan error saat limit terlampaui, dan check yang bersangkutan berstatus `StatusError`.

**T4 — Auto-downgrade saat BSSID berubah.** Simulasikan perubahan BSSID saat run berjalan; assert profil turun ke `passive` dan context dibatalkan.

**T5 — Renderer adalah fungsi murni.** Render seluruh fixture di `testdata/fixtures/` dan bandingkan dengan golden file. Tidak boleh ada akses jaringan selama test ini.

**T6 — Validasi model.** Assert `ValidateCheck` menolak: skipped dengan paket > 0, anomalous non-self-evident dengan confidence high tanpa kontrol, dan kunci penilaian di `Observed`.

**T7 — Verdict wajib punya blind spots.** Assert verdict dengan check skipped tapi `BlindSpots` kosong ditolak.

**T8 — Redaksi output.** Assert JSON hasil tidak pernah mengandung SSID atau BSSID plaintext.

**T9 — Round-trip JSON.** Assert `Result` dapat di-marshal dan di-unmarshal tanpa kehilangan data.

### 8.2 Fixture

Sediakan minimal fixture berikut di `testdata/fixtures/`:

- `clean_home.json` — jaringan bersih, verdict ok
- `corporate_mitm.json` — TLS interception terdeteksi, verdict avoid
- `captive_portal.json` — portal belum login, mayoritas inconclusive
- `open_wifi.json` — jaringan tanpa enkripsi
- `passive_only.json` — banyak blind spot, verdict dengan keyakinan rendah
- `all_failed.json` — seluruh check error, verdict unknown

Fixture ini juga berfungsi sebagai spesifikasi visual untuk renderer.

---

## 9. Antarmuka

### 9.1 CLI

```
wifisec                          jalankan TUI, profil passive
wifisec --profile minimal        jalankan dengan profil tertentu
wifisec --json                   output JSON, tanpa TUI
wifisec --report out.md          ekspor laporan Markdown
wifisec list-checks              tampilkan registry, tanpa menjalankan
wifisec known-networks add       tandai jaringan saat ini sebagai milik sendiri
wifisec control-server --generate  hasilkan skrip listener untuk VPS
```

Flag global: `--no-color`, `--redact` (default true), `--timeout`, `--i-own-this-network`.

### 9.2 Exit code

| Kode | Arti |
|---|---|
| 0 | Selesai, tidak ada finding warning atau critical |
| 1 | Ada finding warning |
| 2 | Ada finding critical |
| 3 | Error internal |
| 4 | Profil tidak mengizinkan operasi yang diminta |

### 9.3 Layar TUI

Empat layar: verdict, findings, detail check, live monitor. Ditambah dialog konfirmasi profil.

**Elemen yang selalu tampil di header:** nama tool, profil aktif dengan glyph (`●` passive, `◐` minimal, `◑` standard, `◆` full), penghitung paket, waktu.

**Aturan render:**

- Setiap status punya glyph pembeda; warna hanya memperkuat, tidak pernah menjadi satu-satunya pembeda
- Breakpoint tunggal di 70 kolom; di bawah itu kolom berdampingan menjadi bertumpuk
- Hasil dirender streaming; check yang belum selesai tampil dengan penanda berjalan
- Verdict sebelum semua check selesai ditandai sementara
- Bagian "tidak diperiksa" mendapat bobot visual setara dengan "temuan utama"
- `false_positive_hints` ditampilkan langsung di finding, tidak disembunyikan
- Setiap layar dapat menyalin JSON-nya dengan satu tombol

Detail visual mengikuti mockup yang sudah disepakati; jika ada keraguan tentang tata letak, tanyakan.

---

## 10. Control server opsional

Diperlukan hanya untuk sebagian check di profil `full`.

`wifisec control-server --generate` menghasilkan satu skrip Go mandiri yang:

- Membuka daftar port yang dikonfigurasi
- Untuk setiap koneksi: terima, balas byte penanda tetap, tutup
- Tidak menyimpan log isi, tidak mem-parse input, tidak menyimpan state
- Berhenti otomatis setelah durasi yang ditentukan (default 15 menit)

Konfigurasi klien di `$XDG_CONFIG_HOME/wifisec/control.yaml` berisi host, daftar port, dan token penanda.

Dokumentasikan bahwa listener sebaiknya tidak dijalankan permanen, dan bahwa membuka banyak port dapat memicu deteksi penyalahgunaan dari penyedia VPS.

---

## 11. Milestone

Urutan mengikat. Guard rail dibangun sebelum kemampuan aktif.

**M1 — Fondasi.** Tipe di Bagian 4, registry loader, fixture, seluruh renderer TUI berjalan dari fixture. Tidak ada kode jaringan sama sekali.
*Selesai bila:* seluruh fixture dapat dirender dan dinavigasi; T5, T6, T7, T9 lulus.

**M2 — Profil pasif.** Adapter platform Linux dan macOS, seluruh check Bagian 6.1, penghitung paket.
*Selesai bila:* T1 lulus termasuk varian network namespace; tool memberikan verdict nyata di jaringan sungguhan.

**M3 — Sistem profil.** Seluruh aturan G1–G7, dialog konfirmasi, whitelist, exit code.
*Selesai bila:* T2, T3, T4 lulus.

**M4 — Check aktif.** Profil `minimal` lalu `standard`. Profil `full` menyusul.
*Selesai bila:* deteksi captive portal berjalan benar dan tidak menghasilkan false positive pada jaringan uji.

**M5 — Rilis.** Dokumentasi, README dengan bagian batasan eksplisit, CI matrix tiga OS, artefak rilis.

---

## 12. Dokumentasi yang wajib dihasilkan

**README.md** wajib memuat, selain penjelasan umum:

- Pernyataan bahwa profil default tidak mengirim paket
- Bagian batasan yang disengaja, menyalin Bagian 0.1 dokumen ini
- Peringatan bahwa profil di atas `passive` sebaiknya hanya dijalankan di jaringan milik sendiri atau dengan izin
- Pernyataan bahwa sebagian besar kode ditulis dengan bantuan AI, beserta tingkat review yang dilakukan
- Cara memverifikasi klaim nol-paket secara mandiri

**CONTRIBUTING.md** wajib menyatakan bahwa PR yang menambahkan kemampuan di Bagian 0.1 akan ditolak tanpa pembahasan.

---

## 13. Pertanyaan yang harus dijawab sebelum M2

Agent wajib menanyakan hal berikut, tidak boleh menebak:

1. Domain kontrol mana yang dipakai untuk `dns.resolve_basic` dan `tls.cert_issuer`
2. Apakah daftar CA publik dibundel dalam binary atau dibaca dari sistem
3. Perilaku aktual pengambilan BSSID di versi macOS target
4. Apakah `wifi.channel_congestion` di profil `full` memerlukan mode monitor, dan jika ya apakah tetap dalam scope
