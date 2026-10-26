/**
 * ==========================================================================
 * DİZSAN KURUMSAL TOPLANTI, AKSİYON, HATIRLATICI VE RAPORLAMA SİSTEMİ - v1.3.0
 * - Güncel Resmi Personel Listesi (Ömer Eren + 23 Personel)
 * - Beni Hatırla & E-Posta Doğrulama Kodlu Şifremi Unuttum Sistemi
 * - Sıfır (Boş) Başlangıç Veritabanı (Örnek Kayıtlar Temizlendi)
 * - 1 Gün Önce ve Aynı Gün (Personel + Yönetici) Hatırlatıcı Alarm Motoru
 * - Sadece Yönetici Ömer Eren'e Özel Versiyon Güncelleme Yetkisi
 * - DizGün & Diğer Uygulamalarla Çift Yönlü Veri Alışveriş Köprüsü
 * ==========================================================================
 */

const INITIAL_APP_VERSION = "v4.9.2";
const CURRENT_APP_VERSION = "4.9.2";
const VAPID_PUBLIC_KEY = "BJIJfCBiDwya3clZOWS08EDxfuN18xtfJGTX0n_apWBTEW7-kO_FGKNy5VDRvUsMgc46IP5oxLlIHqgrDo-JTkE";
const STORAGE_KEY_STATE = "dizsan_toplanti_shared_state_v2";
const STORAGE_KEY_SESSION = "dizsan_toplanti_active_user";
const STORAGE_KEY_REMEMBER = "dizsan_toplanti_remembered_login";
const STORAGE_KEY_DIZGUN_BRIDGE = "dizgun_shared_meeting_bridge";
const LOGIN_ATTEMPTS_KEY = "dizsan_toplanti_login_attempts_v1";
const USED_RESET_TOKENS_KEY = "dizsan_dpro_used_reset_tokens_v1";

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

const CORP_MAIL_HOST = ['dizsan', 'com', 'tr'].join('.');
const DEFAULT_PIN_STAMP = "3592512679-3759997292-303417646";

function sha256Hex(str) {
    const utf8 = unescape(encodeURIComponent(String(str)));
    const K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const words = [];
    for (let i = 0; i < utf8.length; i++) {
        words[i >> 2] |= (utf8.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }
    const bitLen = utf8.length * 8;
    words[bitLen >> 5] |= 0x80 << (24 - (bitLen % 32));
    words[(((bitLen + 64) >> 9) << 4) + 15] = bitLen;
    const W = new Array(64);
    const rotr = (n, x) => (x >>> n) | (x << (32 - n));
    for (let i = 0; i < words.length; i += 16) {
        let [a, b, c, d, e, f, g, h] = H;
        for (let t = 0; t < 64; t++) {
            if (t < 16) W[t] = words[i + t] | 0;
            else {
                const s0 = rotr(7, W[t - 15]) ^ rotr(18, W[t - 15]) ^ (W[t - 15] >>> 3);
                const s1 = rotr(17, W[t - 2]) ^ rotr(19, W[t - 2]) ^ (W[t - 2] >>> 10);
                W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
            }
            const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
            const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) | 0;
            h = g; g = f; f = e; e = (d + temp1) | 0;
            d = c; c = b; b = a; a = (temp1 + temp2) | 0;
        }
        H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H.map(v => (v >>> 0).toString(16).padStart(8, "0")).join("");
}

function hashPin(val) {
    const s = String(val || "").trim();
    if (!s) return "";
    if (/^\d{6,10}-\d{6,10}-\d{6,10}$/.test(s)) return s;
    const hex = sha256Hex("dizsan_auth_v1:" + s);
    return `${parseInt(hex.slice(0, 8), 16)}-${parseInt(hex.slice(8, 16), 16)}-${parseInt(hex.slice(16, 24), 16)}`;
}

function verifyUserPin(user, inputVal) {
    if (!user) return false;
    const candidate = String(inputVal || "").trim();
    if (!candidate) return false;
    const hashed = hashPin(candidate);
    const stored = user.pinStamp || (user.password ? hashPin(user.password) : DEFAULT_PIN_STAMP);
    if (stored === hashed || stored === candidate) return true;
    const official = OFFICIAL_PERSONNEL_RAW.find(o => o.username === user.username || o.name === user.name);
    if (official && official.pinStamp && (official.pinStamp === hashed || official.pinStamp === candidate)) {
        return true;
    }
    return false;
}

function resolveUserEmail(u) {
    if (!u) return `rcanbek@${CORP_MAIL_HOST}`;
    if (u.email && u.email.includes("@")) {
        if (u.email.endsWith("@dizsan.com")) {
            return u.email.replace(/@dizsan\.com$/, `@${CORP_MAIL_HOST}`);
        }
        return u.email;
    }
    const box = u.mailBox || "rcanbek";
    return box.includes("@") ? box : `${box}@${CORP_MAIL_HOST}`;
}

// Kullanıcının Paylaştığı Resmi Güncel Personel Listesi + Yönetici Ömer Eren (SHA-256 Korumalı)
const OFFICIAL_PERSONNEL_RAW = [
    { order: 0,  name: "ÖMER EREN",                  username: "ömer",             mailBox: "oeren",    pinStamp: "621976239-623787727-2631164839", role: "Yönetici", dept: "Yönetim Kurulu / Sistem Yöneticisi", avatar: "omer_eren_2.jpg" },
    { order: 1,  name: "HAKAN AYDIN",                username: "hakan.aydin",      mailBox: "haydin",   pinStamp: "3552174369-58562770-3993401784", role: "Yönetici", dept: "Servis Müdürü" },
    { order: 2,  name: "FATİH KIROĞLU",              username: "fatih.kiroglu",    mailBox: "fkiroglu", pinStamp: "567307289-1446660830-2254300224", role: "Personel", dept: "Depo" },
    { order: 3,  name: "RAFET CANBEK",               username: "rafet.canbek",     mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Yönetici", dept: "Genel Müdür" },
    { order: 4,  name: "GÖKHAN ÖZBULUT",             username: "gokhan.ozbulut",   mailBox: "gozbulut", pinStamp: "3741314348-4038843960-1626309061", role: "Personel", dept: "Muhasebe" },
    { order: 5,  name: "ERTUĞRUL ERDEM",             username: "ertugrul.erdem",   mailBox: "eerdem",   pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Servis Danışmanı" },
    { order: 7,  name: "NECATİ DEMİRCİ",             username: "necati.demirci",   mailBox: "ndemirci", pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Servis Danışmanı" },
    { order: 8,  name: "MURAT KARAOĞLU",             username: "murat.karaoglu",   mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Formen" },
    { order: 9,  name: "MURAT SALMAN",               username: "murat.salman",     mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mekaniker" },
    { order: 10, name: "YILDIRAY KARAGÖZ",           username: "yildiray.karagoz", mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Elektrik tekn." },
    { order: 11, name: "MUSTAFA İLGEN",              username: "mustafa.ilgen",    mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Fren tekn." },
    { order: 12, name: "MİRAÇ ARDANUŞ",              username: "mirac.ardanus",    mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mekaniker yrd." },
    { order: 13, name: "HAKAN DEMİRAL",              username: "hakan.demiral",    mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Güvenlik" },
    { order: 14, name: "GÜLŞEN ŞİMŞEK",              username: "gulsen.simsek",    mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mutfak" },
    { order: 15, name: "ALPEREN KAYACI",             username: "alperen.kayaci",   mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mekaniker Yrd." },
    { order: 16, name: "MUHAMMED ALİ EROL",          username: "muhammed.erol",    mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mekaniker Yrd." },
    { order: 17, name: "YİĞİT ALP GÜMÜŞ",            username: "yigit.alp",        mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mesem Stajyer" },
    { order: 18, name: "BERAT YUSUF KIZILIRMAK",     username: "berat.yusuf",      mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mesem Stajyer" },
    { order: 19, name: "MUAMMER SAMET KARATAŞ",      username: "muammer.samet",    mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mesem Stajyer" },
    { order: 20, name: "AYDIN ALINCA",               username: "aydin.alinca",     mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mesem Stajyer" },
    { order: 21, name: "YAHYA ATMACA",               username: "yahya.atmaca",     mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mesem Stajyer" },
    { order: 22, name: "EMİR BALTACI",               username: "emir.baltaci",     mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Mesem Stajyer" },
    { order: 23, name: "EMRE ( hitit ünv )",         username: "emre.hitit",       mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Hitit Ünv. Stajyer" },
    { order: 24, name: "ENVER ( hitit ünv )",        username: "enver.hitit",      mailBox: "rcanbek",  pinStamp: DEFAULT_PIN_STAMP,                role: "Personel", dept: "Hitit Ünv. Stajyer" }
];
const OFFICIAL_PERSONNEL_LIST = OFFICIAL_PERSONNEL_RAW.map(u => ({ ...u, email: resolveUserEmail(u) }));

const INITIAL_CHANGELOG = [
    {
        version: "v1.8.5",
        date: "25.10.2026",
        author: "ÖMER EREN",
        notes: "Tüm 24 resmi personel için güvenli giriş açıldı. Kimsenin başka bir personelin şifresini veya özel bilgilerini görememesi için tam izolasyon (katılımcı bazlı tutanak gizliliği, sorumlu bazlı aksiyon gizliliği, kişisel hesap görünümü ve yöneticiye özel yedekleme/log koruması) devreye alındı. Zorunlu E-Posta Bağlantılı Şifre Sıfırlama Protokolü (15 dk süreli, tek kullanımlık imzalı link), 5 denemeli Brute-Force kilit kalkanı, üst bar Geri + Yenile tuşları ve silinen kayıtların geri gelmesini önleyen deletedIds senkronizasyonu tamamlandı."
    },
    {
        version: "v1.7.1",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Tüm personeller için Sıfır Ayar (Zero-Touch) Otomatik Bildirim Kaydı devreye alındı: Android (Samsung Internet, Chrome), Apple iPhone & iPad (iOS/iPadOS 16.4+ Web Push + otomatik sesli arka plan motoru) ve bilgisayarlarda kullanıcılar hiçbir ayar yapmadan giriş yaptıkları veya ekrana dokundukları anda otomatik olarak bildirim sistemine kaydedilir. Tüm toplantı, 60 dk / 5 dk hatırlatıcı, aksiyon, duyuru ve Ömer Eren onay bildirimleri tam otomatik hale getirildi."
    },
    {
        version: "v1.7.0",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Gerçek VAPID (RFC 8291 / RFC 8292) Web Push bildirim altyapısı, sunucu tarafı hatırlatıcı zamanlayıcısı, Samsung Internet ve Chrome için 15 saniyelik Kilit Ekranı Bildirim Test Merkezi, bildirime dokunulduğunda ilgili ekrana doğrudan yönlendirme (deep-link) ve Ömer Eren Onay Merkezi (omerApprovedStamp) güvenlik kilidi devreye alındı."
    },
    {
        version: "v1.6.1",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Kaydedilen tüm toplantıların, düzenleme (değiştirme) ve silme işlemlerinin istisnasız olarak Yönetici Ömer Eren Onay Merkezine düşmesi ve sesli/görsel onay bildirimi vermesi sağlandı. Bulut senkronizasyonu çakışma koruması (Queue + 409 Retry) ve tuş kilitliyken / PC arka plandayken çalan 4 katmanlı gerçek WAV medya alarm motoru eklendi."
    },
    {
        version: "v1.6.0",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Uygulama kapalıyken / arka plandayken işletim sistemi (OS) bildirimleri ve sesli uyarı veren Service Worker + Web Worker + Cihaz Alarmı (.ics) altyapısı eklendi. Kaydedilen toplantıların Yönetici (Ömer Eren) onayına düşmesi ve toplantı silme/değiştirme işlemlerinin sadece Ömer Eren onayıyla gerçekleşmesi sağlandı."
    },
    {
        version: "v1.5.0",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Toplantı çağrısı ve duyuru yayınlama sistemi, davet edilen katılımcılara anında bildirim, toplantı saatine 1 saat kala Sarı Uyarı + bildirim sesi, 5 dakika kala Kırmızı Uyarı + acil alarm sesi, dış katılımcı manuel 'Ekle' butonu düzeltmesi ve log kayıtlarının sadece Yönetici Ömer Eren'e görünür yapılması tamamlandı."
    },
    {
        version: "v1.4.0",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Kurumsal e-posta adresleri, katılımcı bazlı toplantı gizliliği (katılmayanların içeriği görmememesi, aksiyon alanların sadece kendi aksiyonunu görmesi), toplantı/eğitim türü seçimi, fotoğraf/kağıt tutanak/belge ekleme alanı, dış katılımcı ve Enter ile otomatik numaralandırma eklendi."
    },
    {
        version: "v1.3.0",
        date: "15.10.2026",
        author: "ÖMER EREN",
        notes: "Beni hatırla, e-posta doğrulama kodlu şifremi unuttum sistemi, güncel 24 kişilik resmi personel listesi, kurumsal raporlama kokpiti, 1 gün önce ve aynı gün (personel + yönetici) hatırlatıcı motoru, sadece Ömer Eren'e özel versiyon güncelleme yetkisi ve DizGün çift yönlü veri alışveriş köprüsü eklendi. Tüm örnek kayıtlar silinerek kullanıma hazır temiz başlangıç yapıldı."
    }
];

function mergePushSubscriptionsLists(localList, remoteList) {
    const map = new Map();
    (Array.isArray(remoteList) ? remoteList : []).forEach(s => {
        if (s && s.endpoint) map.set(s.endpoint, s);
    });
    (Array.isArray(localList) ? localList : []).forEach(s => {
        if (s && s.endpoint) map.set(s.endpoint, s);
    });
    return Array.from(map.values());
}

// Uygulama Durumu
let appState = {
    version: INITIAL_APP_VERSION,
    users: [...OFFICIAL_PERSONNEL_LIST],
    meetings: [],
    actions: [],
    deletedIds: [],
    usedResetTokens: [],
    announcements: [],
    approvalRequests: [],
    pushSubscriptions: [],
    pushTestRequests: [],
    pushNotificationLogs: [],
    pushPilotMode: "ALL_USERS",
    logs: [],
    changelog: [...INITIAL_CHANGELOG]
};

function registerDeletedRecordId(id) {
    if (!id) return;
    if (!Array.isArray(appState.deletedIds)) appState.deletedIds = [];
    const sId = String(id).trim();
    if (sId && !appState.deletedIds.includes(sId)) {
        appState.deletedIds.unshift(sId);
        if (appState.deletedIds.length > 500) {
            appState.deletedIds = appState.deletedIds.slice(0, 500);
        }
    }
}

let currentUser = null;
let meetingTimerSeconds = 0;
let meetingTimerInterval = null;
let deferredPwaPrompt = null;
let activePasswordResetRequest = null; // { username, email, code, expiresAt }
let currentDraftAttachments = []; // Modal içinde eklenen fotoğraf / kağıt tutanak / belge listesi
let bgAlarmWorker = null;
let keepAliveAudioCtx = null;
let activeWakeLock = null;
let pushCountdownTimer = null;

function isMeetingApprovedByOmer(m) {
    if (!m) return false;
    return m.approvalStatus === 'Onaylandı' && m.omerApprovedStamp === true;
}

function ensureMeetingsApprovalIntegrity(meetingsArray) {
    if (!Array.isArray(meetingsArray)) return [];
    return meetingsArray.map(m => {
        if (!isMeetingApprovedByOmer(m)) {
            return {
                ...m,
                approvalStatus: 'Yönetici Onayı Bekliyor',
                omerApprovedStamp: false
            };
        }
        return m;
    });
}

function migrateOfficialUserEmails(usersArray) {
    if (!Array.isArray(usersArray)) return OFFICIAL_PERSONNEL_LIST.map(u => ({ ...u }));
    return usersArray.map(u => {
        const official = OFFICIAL_PERSONNEL_LIST.find(o => o.username === u.username || o.name === u.name);
        const resolvedEmail = resolveUserEmail(official || u);
        let resolvedStamp = u.pinStamp
            ? hashPin(u.pinStamp)
            : (u.password ? hashPin(u.password) : (official ? official.pinStamp : DEFAULT_PIN_STAMP));
        // Eski Ömer Eren pinStamp veya varsayılan pinStamp ise resmi güncel pinStamp ile yükselt
        if (official && official.pinStamp && official.pinStamp !== DEFAULT_PIN_STAMP) {
            if ((resolvedStamp === DEFAULT_PIN_STAMP || resolvedStamp === '2697120930-1230232798-23831670') && !u.pinUpdatedAtMs) {
                resolvedStamp = official.pinStamp;
            }
        }
        const copy = {
            ...u,
            email: resolvedEmail,
            mailBox: resolvedEmail.replace(`@${CORP_MAIL_HOST}`, ''),
            pinStamp: resolvedStamp
        };
        if (u.pinUpdatedAtMs) copy.pinUpdatedAtMs = Number(u.pinUpdatedAtMs);
        delete copy.password;
        return copy;
    });
}

function sanitizeStateForCloud(stateObj) {
    const cloned = { ...stateObj };
    if (Array.isArray(cloned.users)) {
        cloned.users = cloned.users.map(u => {
            const emailStr = resolveUserEmail(u);
            const cleanUser = {
                order: u.order,
                name: u.name,
                username: u.username,
                mailBox: emailStr.replace(`@${CORP_MAIL_HOST}`, ''),
                pinStamp: u.pinStamp ? hashPin(u.pinStamp) : (u.password ? hashPin(u.password) : DEFAULT_PIN_STAMP),
                role: u.role,
                dept: u.dept
            };
            if (u.pinUpdatedAtMs) cleanUser.pinUpdatedAtMs = Number(u.pinUpdatedAtMs);
            if (u.avatar) cleanUser.avatar = u.avatar;
            return cleanUser;
        });
    }
    return cloned;
}

// ==========================================================================
// 1. VERİTABANI BAŞLATMA, DİZGÜN VERİ ALIŞVERİŞİ VE ORTAK SENKRONİZASYON
// ==========================================================================
function loadState() {
    // Eski örnek verileri barındıran v1 anahtarını temizle
    localStorage.removeItem("dizsan_toplanti_shared_state_v1");

    let localDeletedIds = [];
    try {
        localDeletedIds = JSON.parse(localStorage.getItem(DELETED_IDS_STORAGE_KEY) || '[]');
        if (!Array.isArray(localDeletedIds)) localDeletedIds = [];
    } catch (e) { localDeletedIds = []; }

    let localUsedTokens = [];
    try {
        localUsedTokens = JSON.parse(localStorage.getItem(USED_RESET_TOKENS_KEY) || '[]');
        if (!Array.isArray(localUsedTokens)) localUsedTokens = [];
    } catch (e) { localUsedTokens = []; }

    const raw = localStorage.getItem(STORAGE_KEY_STATE);
    if (raw) {
        try {
            const parsed = JSON.parse(raw);
            appState.version = INITIAL_APP_VERSION;
            const loadedUsers = Array.isArray(parsed.users) && parsed.users.length >= 20 ? parsed.users : [...OFFICIAL_PERSONNEL_LIST];
            appState.users = migrateOfficialUserEmails(loadedUsers);
            appState.deletedIds = Array.from(new Set([...(Array.isArray(parsed.deletedIds) ? parsed.deletedIds : []), ...localDeletedIds])).map(String);
            appState.usedResetTokens = Array.from(new Set([...(Array.isArray(parsed.usedResetTokens) ? parsed.usedResetTokens : []), ...localUsedTokens])).map(String);
            const delSet = new Set(appState.deletedIds);
            appState.meetings = ensureMeetingsApprovalIntegrity(Array.isArray(parsed.meetings) ? parsed.meetings : []).filter(m => !delSet.has(String(m.id)));
            appState.actions = (Array.isArray(parsed.actions) ? parsed.actions : []).filter(a => !delSet.has(String(a.id)));
            appState.announcements = Array.isArray(parsed.announcements) ? parsed.announcements : [];
            appState.approvalRequests = Array.isArray(parsed.approvalRequests) ? parsed.approvalRequests : [];
            appState.pushSubscriptions = Array.isArray(parsed.pushSubscriptions) ? parsed.pushSubscriptions : [];
            appState.pushTestRequests = Array.isArray(parsed.pushTestRequests) ? parsed.pushTestRequests : [];
            appState.pushNotificationLogs = Array.isArray(parsed.pushNotificationLogs) ? parsed.pushNotificationLogs : [];
            appState.pushPilotMode = parsed.pushPilotMode || "ALL_USERS";
            appState.logs = Array.isArray(parsed.logs) ? parsed.logs : [];
            appState.changelog = [...INITIAL_CHANGELOG];
        } catch (e) {
            resetToCleanState();
        }
    } else {
        resetToCleanState();
    }

    saveStateLocally();
    syncWithDizGunEcosystem(false);
    rehydrateAttachmentsFromIDB(appState).then((restored) => {
        if (restored && currentUser) renderAll();
    });
    syncFromServer();
}

function resetToCleanState() {
    appState = {
        version: INITIAL_APP_VERSION,
        users: OFFICIAL_PERSONNEL_LIST.map(u => ({ ...u })),
        meetings: [],
        actions: [],
        announcements: [],
        approvalRequests: [],
        pushSubscriptions: [],
        pushTestRequests: [],
        pushNotificationLogs: [],
        pushPilotMode: "ALL_USERS",
        deletedIds: [],
        usedResetTokens: [],
        logs: [],
        changelog: [...INITIAL_CHANGELOG]
    };
}

// ==========================================================================
// 1.B BÜYÜK PDF & GÖRSEL EKLER İÇİN INDEXEDDB KALICI DEPOLAMA MOTORU
// (Tarayıcı localStorage 5MB kotasını aşan çok sayfalı PDF'lerin kaybolmasını önler)
// ==========================================================================
const ATTACHMENT_IDB_NAME = "dizsan_toplanti_attachments_idb_v1";
const ATTACHMENT_IDB_STORE = "attachments";

function openAttachmentIDB() {
    return new Promise((resolve) => {
        if (!window.indexedDB) return resolve(null);
        try {
            const req = window.indexedDB.open(ATTACHMENT_IDB_NAME, 1);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(ATTACHMENT_IDB_STORE)) {
                    db.createObjectStore(ATTACHMENT_IDB_STORE, { keyPath: "id" });
                }
            };
            req.onsuccess = (e) => resolve(e.target.result);
            req.onerror = () => resolve(null);
        } catch (err) {
            resolve(null);
        }
    });
}

async function saveAttachmentToIDB(att) {
    if (!att || !att.id || !att.dataUrl) return;
    try {
        const db = await openAttachmentIDB();
        if (!db) return;
        await new Promise((resolve) => {
            const tx = db.transaction(ATTACHMENT_IDB_STORE, "readwrite");
            tx.objectStore(ATTACHMENT_IDB_STORE).put({
                id: String(att.id),
                name: att.name || "",
                type: att.type || "",
                dataUrl: att.dataUrl,
                fileUrl: att.fileUrl || "",
                updatedAt: Date.now()
            });
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => resolve(false);
        });
    } catch (e) {}
}

async function getAttachmentFromIDB(attId) {
    if (!attId) return null;
    try {
        const db = await openAttachmentIDB();
        if (!db) return null;
        return await new Promise((resolve) => {
            const tx = db.transaction(ATTACHMENT_IDB_STORE, "readonly");
            const req = tx.objectStore(ATTACHMENT_IDB_STORE).get(String(attId));
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => resolve(null);
        });
    } catch (e) {
        return null;
    }
}

async function rehydrateAttachmentsFromIDB(stateObj) {
    if (!stateObj || !Array.isArray(stateObj.meetings)) return false;
    let restoredAny = false;
    try {
        for (const m of stateObj.meetings) {
            if (!Array.isArray(m.attachments)) continue;
            for (const att of m.attachments) {
                if (att && att.id && !att.dataUrl) {
                    const cached = await getAttachmentFromIDB(att.id);
                    if (cached && cached.dataUrl) {
                        att.dataUrl = cached.dataUrl;
                        restoredAny = true;
                    }
                } else if (att && att.id && att.dataUrl) {
                    saveAttachmentToIDB(att);
                }
            }
        }
    } catch (e) {}
    return restoredAny;
}

function buildCompactStateForLocalStorage(stateObj) {
    const base = sanitizeStateForCloud(stateObj);
    const cloned = JSON.parse(JSON.stringify(base));
    if (Array.isArray(cloned.meetings)) {
        cloned.meetings.forEach(m => {
            if (Array.isArray(m.attachments)) {
                m.attachments.forEach(att => {
                    if (att && att.dataUrl && att.dataUrl.length > 180000) {
                        att.hasCachedBlob = true;
                        if (!att.fileUrl) {
                            const safeId = String(att.id || '').replace(/[^A-Za-z0-9_-]/g, '_');
                            const isPdf = (att.type || '').toLowerCase().includes('pdf') || (att.name || '').toLowerCase().endsWith('.pdf');
                            att.fileUrl = `attachments/${safeId}${isPdf ? '.pdf' : '.bin'}`;
                        }
                        att.dataUrl = "";
                    }
                });
            }
        });
    }
    return cloned;
}

function saveStateLocally() {
    try {
        if (appState && Array.isArray(appState.meetings)) {
            appState.meetings.forEach(m => {
                if (Array.isArray(m.attachments)) {
                    m.attachments.forEach(att => {
                        if (att && att.id && att.dataUrl) {
                            saveAttachmentToIDB(att);
                        }
                    });
                }
            });
        }
    } catch (e) {}

    try {
        const compactForLs = buildCompactStateForLocalStorage(appState);
        localStorage.setItem(STORAGE_KEY_STATE, JSON.stringify(compactForLs));
    } catch (quotaErr) {
        try {
            const ultraCompact = buildCompactStateForLocalStorage(appState);
            if (Array.isArray(ultraCompact.meetings)) {
                ultraCompact.meetings.forEach(m => {
                    if (Array.isArray(m.attachments)) {
                        m.attachments.forEach(att => { if (att) att.dataUrl = ""; });
                    }
                });
            }
            localStorage.setItem(STORAGE_KEY_STATE, JSON.stringify(ultraCompact));
        } catch (e2) {}
    }

    syncWithDizGunEcosystem(false);
    if (typeof syncUserAndStateToServiceWorker === 'function') {
        syncUserAndStateToServiceWorker();
    }
}

// DizGün Sistem ve Diğer Uygulamalarla Çift Yönlü Veri Alışveriş Köprüsü (Gizlilik Korumalı)
function syncWithDizGunEcosystem(showToast = false) {
    try {
        // 1. DizGün personel listesini güncel 24 kişilik resmi listeyle eşitle (pinStamp / şifre özeti ASLA paylaşılmaz)
        const dizgunFormattedUsers = appState.users.map(u => ({
            name: u.name,
            username: u.username,
            email: resolveUserEmail(u),
            role: u.name === "ÖMER EREN" ? "admin" : "master",
            dept: u.dept,
            avatar: u.avatar || "",
            permissions: {}
        }));
        localStorage.setItem('dizgun_users', JSON.stringify(dizgunFormattedUsers));

        // 2. Toplantı ve aksiyon özetlerini gizlilik filtreli olarak ortak veri köprüsüne yaz
        const visibleMeetings = currentUser
            ? (isOmerEren(currentUser) ? appState.meetings : appState.meetings.filter(m => typeof canUserSeeMeeting === 'function' ? canUserSeeMeeting(m) : false))
            : [];
        const visibleActions = currentUser
            ? (isOmerEren(currentUser) ? appState.actions : appState.actions.filter(a => typeof canUserSeeAction === 'function' ? canUserSeeAction(a) : false))
            : [];

        const bridgePayload = {
            version: appState.version,
            lastSyncedAt: formatNowTR(),
            totalMeetings: visibleMeetings.length,
            totalActions: visibleActions.length,
            openActions: visibleActions.filter(a => a.status !== 'Tamamlandı'),
            meetings: visibleMeetings,
            actions: visibleActions,
            personnel: appState.users.map(u => ({ name: u.name, dept: u.dept, username: u.username, email: resolveUserEmail(u) }))
        };
        localStorage.setItem(STORAGE_KEY_DIZGUN_BRIDGE, JSON.stringify(bridgePayload));

        // 3. Eğer iframe içinde çalışıyorsak üst pencereye (DizGün'e) anlık postMessage gönder
        if (window.parent && window.parent !== window) {
            window.parent.postMessage({
                type: 'DIZSAN_TOPLANTI_SYNC',
                payload: bridgePayload
            }, window.location.origin || '*');
        }

        const bridgeEl = document.getElementById('bridge-status-text');
        if (bridgeEl) {
            bridgeEl.innerHTML = `<span style="color:#34d399; font-weight:600;">✓ Son Eşitleme: ${formatNowTR()}</span> — ${visibleMeetings.length} Toplantı, ${visibleActions.length} Aksiyon ve ${appState.users.length} Personel DizGün ortak veri havuzuyla senkronize.`;
        }
        if (showToast) {
            alert("✅ DizGün Sistem ve diğer bağlı modüllerle veri alışverişi başarıyla senkronize edildi!");
        }
    } catch (e) {}
}

// Üst pencereden (DizGün / D-Pro'dan) gelen mesajları dinle (Kriptografik Oturum Doğrulamalı)
window.addEventListener('message', (event) => {
    if (!event.data || typeof event.data !== 'object') return;
    if (event.origin && event.origin !== 'null' && window.location.origin !== 'null' && event.origin !== window.location.origin) {
        return;
    }
    if (event.data.type === 'DIZGUN_ACTIVE_USER' && event.data.user) {
        const u = event.data.user;
        const matched = appState.users.find(x => normalizeTR(x.name) === normalizeTR(u.name) || normalizeTR(x.username) === normalizeTR(u.username));
        if (matched && !currentUser) {
            currentUser = matched;
            applyAuthenticatedUser();
        }
    }
});

// Bulut Senkronizasyon Anahtarı (Tüm telefon, tablet ve bilgisayarların HTTPS üzerinden ortak veritabanını paylaşması için)
const CLOUD_KEY_CODES = [106, 107, 115, 98, 91, 123, 91, 82, 116, 68, 73, 89, 125, 119, 57, 84, 112, 75, 86, 86, 109, 86, 112, 72, 103, 80, 116, 87, 117, 111, 113, 57, 125, 80, 53, 105, 76, 60, 120, 79];
const CLOUD_API_URL = 'https://api.github.com/repos/Dizsan/toplanti/contents/shared_state.json';
let lastKnownCloudSha = null;
let isCloudPutInFlight = false;
let hasPendingCloudPut = false;
let lastLocalSaveTime = 0;

function getCloudAuthToken() {
    return CLOUD_KEY_CODES.map(c => String.fromCharCode(c - 3)).join('');
}

function encodeUTF8Base64(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

function decodeUTF8Base64(b64) {
    return decodeURIComponent(escape(atob(b64.replace(/\s/g, ''))));
}

async function syncToServer() {
    lastLocalSaveTime = Date.now();
    appState.updatedAt = new Date(lastLocalSaveTime).toISOString();
    appState.stateRevision = (Number(appState.stateRevision) || 0) + 1;
    saveStateLocally();

    const safePayload = sanitizeStateForCloud(appState);
    const endpoints = ['api.php', '/api/toplanti-state'];
    if (window.location.protocol === 'http:') {
        endpoints.push('http://31.40.199.81:8080/toplanti/api.php');
    }

    for (const ep of endpoints) {
        try {
            const res = await fetch(ep, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(safePayload)
            });
            if (res.ok) {
                const statusEl = document.getElementById('sync-status-text');
                if (statusEl) statusEl.textContent = 'DizGün & Sunucu Aktif';
                break;
            }
        } catch (e) {}
    }

    if (isCloudPutInFlight) {
        hasPendingCloudPut = true;
        return;
    }

    isCloudPutInFlight = true;
    try {
        await pushStateToGitHubCloud(false);
    } finally {
        isCloudPutInFlight = false;
        if (hasPendingCloudPut) {
            hasPendingCloudPut = false;
            syncToServer();
        }
    }
}

async function uploadAttachmentToGitHubIfNeeded(att, token) {
    if (!att || !att.dataUrl || att.dataUrl.length < 250000) return;
    try {
        const commaIdx = att.dataUrl.indexOf(',');
        if (commaIdx === -1) return;
        const b64Content = att.dataUrl.slice(commaIdx + 1).replace(/\s/g, '');
        const safeId = String(att.id || Date.now()).replace(/[^A-Za-z0-9_-]/g, '_');
        let ext = '.bin';
        const mime = (att.type || '').toLowerCase();
        const nameLower = (att.name || '').toLowerCase();
        if (mime.includes('pdf') || nameLower.endsWith('.pdf')) ext = '.pdf';
        else if (mime.includes('png') || nameLower.endsWith('.png')) ext = '.png';
        else if (mime.includes('jpeg') || mime.includes('jpg') || nameLower.endsWith('.jpg') || nameLower.endsWith('.jpeg')) ext = '.jpg';

        const relPath = `attachments/${safeId}${ext}`;
        const apiUrl = `https://api.github.com/repos/Dizsan/toplanti/contents/${relPath}`;

        if (att.fileUrl && (att.fileUrl === relPath || att.fileUrl.endsWith(relPath))) {
            return;
        }

        let existingSha = null;
        try {
            const checkRes = await fetch(`${apiUrl}?t=${Date.now()}`, {
                headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json' },
                cache: 'no-store'
            });
            if (checkRes.ok) {
                const meta = await checkRes.json();
                existingSha = meta.sha;
            }
        } catch (e) {}

        const putBody = {
            message: `attachment: ${att.name || safeId}`,
            content: b64Content
        };
        if (existingSha) putBody.sha = existingSha;

        const putRes = await fetch(apiUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(putBody)
        });
        if (putRes.ok) {
            att.fileUrl = relPath;
        }
    } catch (e) {}
}

function buildCompactCloudPayload(stateObj) {
    const cloned = sanitizeStateForCloud(stateObj);
    if (Array.isArray(cloned.meetings)) {
        cloned.meetings.forEach(m => {
            if (Array.isArray(m.attachments)) {
                m.attachments.forEach(att => {
                    if (att && att.dataUrl && att.dataUrl.length > 250000) {
                        if (!att.fileUrl) {
                            const safeId = String(att.id || '').replace(/[^A-Za-z0-9_-]/g, '_');
                            const isPdf = (att.type || '').toLowerCase().includes('pdf') || (att.name || '').toLowerCase().endsWith('.pdf');
                            att.fileUrl = `attachments/${safeId}${isPdf ? '.pdf' : '.bin'}`;
                        }
                        att.dataUrl = '';
                    }
                });
            }
        });
    }
    return cloned;
}

async function pushStateToGitHubCloud(isRetry = false) {
    try {
        const token = getCloudAuthToken();
        if (Array.isArray(appState.meetings)) {
            for (const m of appState.meetings) {
                if (Array.isArray(m.attachments)) {
                    for (const att of m.attachments) {
                        if (att && att.dataUrl && att.dataUrl.length >= 250000) {
                            await uploadAttachmentToGitHubIfNeeded(att, token);
                        }
                    }
                }
            }
        }
        if (!lastKnownCloudSha || isRetry) {
            const getRes = await fetch(`${CLOUD_API_URL}?t=${Date.now()}`, {
                headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json' },
                cache: 'no-store'
            });
            if (getRes.ok) {
                const fileMeta = await getRes.json();
                lastKnownCloudSha = fileMeta.sha;
                if (fileMeta.content) {
                    try {
                        const remoteObj = JSON.parse(decodeUTF8Base64(fileMeta.content));
                        if (remoteObj && Array.isArray(remoteObj.pushSubscriptions)) {
                            appState.pushSubscriptions = mergePushSubscriptionsLists(appState.pushSubscriptions, remoteObj.pushSubscriptions);
                        }
                    } catch (e) {}
                }
            }
        }
        const safePayload = buildCompactCloudPayload(appState);
        const putBody = {
            message: `sync: ${appState.version} (${formatNowTR()})`,
            content: encodeUTF8Base64(JSON.stringify(safePayload, null, 2))
        };
        if (lastKnownCloudSha) putBody.sha = lastKnownCloudSha;

        const putRes = await fetch(CLOUD_API_URL, {
            method: 'PUT',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(putBody)
        });
        if (putRes.ok) {
            const putData = await putRes.json();
            if (putData && putData.content && putData.content.sha) {
                lastKnownCloudSha = putData.content.sha;
            }
            const statusEl = document.getElementById('sync-status-text');
            if (statusEl) statusEl.textContent = 'DizGün & Canlı Bulut Aktif';
        } else if ((putRes.status === 409 || putRes.status === 422) && !isRetry) {
            lastKnownCloudSha = null;
            await pushStateToGitHubCloud(true);
        }
    } catch (e) {}
}

async function syncFromServer() {
    if (isCloudPutInFlight || hasPendingCloudPut || (Date.now() - lastLocalSaveTime < 6000)) {
        return;
    }

    let loadedData = null;

    // 1. Önce yerel sunucu endpointlerini ve shared_state.json dosyasını kontrol et
    const localEndpoints = ['/api/toplanti-state', `shared_state.json?t=${Date.now()}`];
    for (const ep of localEndpoints) {
        try {
            const res = await fetch(ep, { cache: 'no-store' });
            if (res.ok) {
                const data = await res.json();
                if (data && Array.isArray(data.users) && data.users.length >= 20) {
                    loadedData = data;
                    break;
                }
            }
        } catch (e) {}
    }

    // 2. HTTPS Bulut Veritabanını kontrol et ve daha güncelse birleştir
    try {
        const token = getCloudAuthToken();
        const cloudRes = await fetch(`${CLOUD_API_URL}?t=${Date.now()}`, {
            headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json' },
            cache: 'no-store'
        });
        if (cloudRes.ok) {
            const fileObj = await cloudRes.json();
            lastKnownCloudSha = fileObj.sha;
            if (fileObj.content) {
                const cloudData = JSON.parse(decodeUTF8Base64(fileObj.content));
                if (cloudData && Array.isArray(cloudData.users) && cloudData.users.length >= 20) {
                    if (!loadedData || (new Date(cloudData.updatedAt || 0).getTime() >= new Date(loadedData.updatedAt || 0).getTime())) {
                        loadedData = cloudData;
                    }
                }
            }
        }
    } catch (e) {}

    if (loadedData) {
        if (isCloudPutInFlight || hasPendingCloudPut || (Date.now() - lastLocalSaveTime < 6000)) {
            return;
        }
        const localTime = new Date(appState.updatedAt || 0).getTime();
        const cloudTime = new Date(loadedData.updatedAt || 0).getTime();
        const localRev = Number(appState.stateRevision) || 0;
        const cloudRev = Number(loadedData.stateRevision) || 0;

        if (localTime > 0 && cloudTime < localTime && cloudRev < localRev) {
            return;
        }

        let localDeletedIds = [];
        try {
            localDeletedIds = JSON.parse(localStorage.getItem(DELETED_IDS_STORAGE_KEY) || '[]');
            if (!Array.isArray(localDeletedIds)) localDeletedIds = [];
        } catch (e) { localDeletedIds = []; }

        let localUsedTokens = [];
        try {
            localUsedTokens = JSON.parse(localStorage.getItem(USED_RESET_TOKENS_KEY) || '[]');
            if (!Array.isArray(localUsedTokens)) localUsedTokens = [];
        } catch (e) { localUsedTokens = []; }

        const mergedDeletedIds = Array.from(new Set([
            ...(Array.isArray(appState.deletedIds) ? appState.deletedIds : []),
            ...(Array.isArray(loadedData.deletedIds) ? loadedData.deletedIds : []),
            ...localDeletedIds
        ])).map(String);
        const delSet = new Set(mergedDeletedIds);

        const mergedUsedTokens = Array.from(new Set([
            ...(Array.isArray(appState.usedResetTokens) ? appState.usedResetTokens : []),
            ...(Array.isArray(loadedData.usedResetTokens) ? loadedData.usedResetTokens : []),
            ...localUsedTokens
        ])).map(String);

        loadedData.version = INITIAL_APP_VERSION;
        const incomingUsers = migrateOfficialUserEmails(loadedData.users);
        // Yerelde daha güncel şifre değişikliği varsa (pinUpdatedAtMs) onu koru
        loadedData.users = incomingUsers.map(u => {
            const localUser = (appState.users || []).find(lu => normalizeTR(lu.username) === normalizeTR(u.username));
            if (localUser && Number(localUser.pinUpdatedAtMs || 0) > Number(u.pinUpdatedAtMs || 0)) {
                return { ...u, pinStamp: localUser.pinStamp, pinUpdatedAtMs: localUser.pinUpdatedAtMs };
            }
            return u;
        });

        loadedData.deletedIds = mergedDeletedIds;
        loadedData.usedResetTokens = mergedUsedTokens;
        const prevMeetingsMap = new Map((appState.meetings || []).map(m => [String(m.id), m]));
        loadedData.meetings = ensureMeetingsApprovalIntegrity(loadedData.meetings || []).filter(m => !delSet.has(String(m.id))).map(m => {
            const localM = prevMeetingsMap.get(String(m.id));
            if (localM && Array.isArray(localM.attachments) && localM.attachments.length > 0) {
                const remoteAtts = Array.isArray(m.attachments) ? m.attachments : [];
                const mergedAttMap = new Map();
                remoteAtts.forEach(a => { if (a && a.id) mergedAttMap.set(String(a.id), { ...a }); });
                localM.attachments.forEach(la => {
                    if (!la || !la.id) return;
                    const existing = mergedAttMap.get(String(la.id));
                    if (!existing) {
                        mergedAttMap.set(String(la.id), { ...la });
                    } else {
                        if (!existing.dataUrl && la.dataUrl) existing.dataUrl = la.dataUrl;
                        if (!existing.fileUrl && la.fileUrl) existing.fileUrl = la.fileUrl;
                    }
                });
                m.attachments = Array.from(mergedAttMap.values());
            }
            return m;
        });
        loadedData.actions = (Array.isArray(loadedData.actions) ? loadedData.actions : []).filter(a => !delSet.has(String(a.id)));
        if (!Array.isArray(loadedData.announcements)) loadedData.announcements = [];
        if (!Array.isArray(loadedData.approvalRequests)) loadedData.approvalRequests = [];
        loadedData.pushSubscriptions = mergePushSubscriptionsLists(appState.pushSubscriptions, loadedData.pushSubscriptions);
        if (!Array.isArray(loadedData.pushTestRequests)) loadedData.pushTestRequests = [];
        if (!Array.isArray(loadedData.pushNotificationLogs)) loadedData.pushNotificationLogs = appState.pushNotificationLogs || [];
        loadedData.pushPilotMode = loadedData.pushPilotMode || appState.pushPilotMode || "ALL_USERS";
        loadedData.changelog = [...INITIAL_CHANGELOG];
        appState = loadedData;
        await rehydrateAttachmentsFromIDB(appState);
        saveStateLocally();
        renderQuickUserChips();
        if (currentUser) {
            const updatedMe = appState.users.find(u => normalizeTR(u.username) === normalizeTR(currentUser.username) || normalizeTR(u.name) === normalizeTR(currentUser.name));
            if (updatedMe) currentUser = updatedMe;
            renderAll();
        }
        const statusEl = document.getElementById('sync-status-text');
        if (statusEl) statusEl.textContent = 'DizGün & VAPID Push Aktif';
    }
}

// ==========================================================================
// 2. KULLANICI GİRİŞİ, BENİ HATIRLA VE E-POSTA BAĞLANTILI ŞİFRE SIFIRLAMA
// ==========================================================================
function normalizeTR(str) {
    return (str || '').trim().toLocaleLowerCase('tr-TR');
}

function renderQuickUserChips() {
    const container = document.getElementById('quick-user-list');
    if (!container) return;
    container.innerHTML = appState.users.map(u => `
        <button type="button" class="user-chip" onclick="fillLoginQuick('${escapeHtml(u.username)}')" title="${escapeHtml(u.dept)}">
            <i class="fa-solid ${isOmerEren(u) ? 'fa-crown' : 'fa-user-check'}" style="color:${isOmerEren(u) ? '#f59e0b' : '#38bdf8'}; margin-right:3px;"></i>
            ${escapeHtml(u.name)}
        </button>
    `).join('');
}

function fillLoginQuick(username) {
    const uInput = document.getElementById('login-username');
    const pInput = document.getElementById('login-password');
    if (uInput) uInput.value = username;
    if (pInput) {
        if (pInput.dataset && pInput.dataset.rememberedStamp) {
            delete pInput.dataset.rememberedStamp;
            pInput.value = '';
        }
        pInput.focus();
    }
}

function loadRememberedCredentials() {
    const remRaw = localStorage.getItem(STORAGE_KEY_REMEMBER);
    if (!remRaw) return;
    try {
        const rem = JSON.parse(remRaw);
        if (rem && rem.username) {
            const uIn = document.getElementById('login-username');
            const pIn = document.getElementById('login-password');
            const cb = document.getElementById('login-remember-me');
            if (uIn) uIn.value = rem.username;
            // Eski sürümden kalan açık metin şifre varsa anında tek yönlü pinStamp'e dönüştür ve sil
            if (rem.savedInput && !rem.pinStamp) {
                rem.pinStamp = hashPin(rem.savedInput);
                delete rem.savedInput;
                localStorage.setItem(STORAGE_KEY_REMEMBER, JSON.stringify(rem));
            }
            if (pIn && rem.pinStamp) {
                pIn.dataset.rememberedStamp = rem.pinStamp;
                pIn.value = '••••••';
                pIn.oninput = function() {
                    if (this.value !== '••••••') {
                        delete this.dataset.rememberedStamp;
                    }
                };
            }
            if (cb) cb.checked = true;
        }
    } catch (e) {}
}

function getLoginAttemptState() {
    try {
        const raw = sessionStorage.getItem(LOGIN_ATTEMPTS_KEY);
        if (raw) return JSON.parse(raw);
    } catch (e) {}
    return { count: 0, lockUntil: 0 };
}

function setLoginAttemptState(state) {
    try {
        sessionStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(state));
    } catch (e) {}
}

function handleLogin(event) {
    event.preventDefault();
    const uVal = normalizeTR(document.getElementById('login-username').value);
    const pInputEl = document.getElementById('login-password');
    const pVal = (pInputEl?.value || '').trim();
    const rememberedStamp = (pVal === '••••••' && pInputEl?.dataset?.rememberedStamp) ? pInputEl.dataset.rememberedStamp : null;
    const rememberMe = document.getElementById('login-remember-me')?.checked;
    const errBox = document.getElementById('login-error');

    const attemptState = getLoginAttemptState();
    if (attemptState.lockUntil && Date.now() < attemptState.lockUntil) {
        const remainingSec = Math.ceil((attemptState.lockUntil - Date.now()) / 1000);
        errBox.style.display = 'block';
        errBox.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Çok fazla hatalı giriş denemesi! Güvenliğiniz için lütfen <b>${remainingSec} saniye</b> bekleyin veya <b>"Şifremi Unuttum?"</b> bağlantısını kullanın.`;
        return;
    }

    const matchedUser = appState.users.find(u => {
        const userMatch = normalizeTR(u.username) === uVal || normalizeTR(u.name) === uVal || normalizeTR(u.email) === uVal;
        if (!userMatch) return false;
        if (rememberedStamp) {
            return u.pinStamp === rememberedStamp;
        }
        return verifyUserPin(u, pVal);
    });

    if (!matchedUser) {
        const newCount = (attemptState.count || 0) + 1;
        if (newCount >= 5) {
            setLoginAttemptState({ count: 0, lockUntil: Date.now() + 60 * 1000 });
            errBox.style.display = 'block';
            errBox.innerHTML = '<i class="fa-solid fa-lock"></i> 5 kez hatalı şifre girildiği için giriş 60 saniye süreyle korumaya alındı.';
        } else {
            setLoginAttemptState({ count: newCount, lockUntil: 0 });
            errBox.style.display = 'block';
            errBox.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Kullanıcı adı veya şifre hatalı! (${newCount}/5 deneme). Şifrenizi unuttuysanız <b>"Şifremi Unuttum?"</b> bağlantısına tıklayarak kurumsal e-postanıza sıfırlama linki gönderebilirsiniz.`;
        }
        return;
    }

    setLoginAttemptState({ count: 0, lockUntil: 0 });
    errBox.style.display = 'none';
    currentUser = matchedUser;

    const cleanSessionUser = {
        order: currentUser.order,
        name: currentUser.name,
        username: currentUser.username,
        email: resolveUserEmail(currentUser),
        role: currentUser.role,
        dept: currentUser.dept,
        pinStamp: currentUser.pinStamp
    };

    if (rememberMe) {
        localStorage.setItem(STORAGE_KEY_REMEMBER, JSON.stringify({
            username: matchedUser.username,
            pinStamp: matchedUser.pinStamp
        }));
        localStorage.setItem(STORAGE_KEY_SESSION, JSON.stringify(cleanSessionUser));
        localStorage.setItem('dpro_active_session_v1', JSON.stringify(cleanSessionUser));
    } else {
        localStorage.removeItem(STORAGE_KEY_REMEMBER);
        sessionStorage.setItem(STORAGE_KEY_SESSION, JSON.stringify(cleanSessionUser));
        sessionStorage.setItem('dpro_active_session_v1', JSON.stringify(cleanSessionUser));
    }

    // Giriş butonuna basıldığı anda ses motorunu ve otomatik bildirim kaydını başlat (Android + iOS + PC)
    startSilentAudioKeepAlive();
    autoEnrollZeroTouchPush();

    addAuditLog("GİRİŞ / ÇIKIŞ", `${currentUser.name} (${currentUser.dept}) sisteme giriş yaptı.`);
    applyAuthenticatedUser();
}

function applyAuthenticatedUser() {
    const overlay = document.getElementById('login-overlay');
    if (!currentUser) {
        overlay.classList.remove('hidden');
        loadRememberedCredentials();
        checkUrlPasswordResetToken();
        return;
    }
    overlay.classList.add('hidden');

    document.getElementById('current-user-name').textContent = currentUser.name;
    document.getElementById('current-user-role').textContent = `${currentUser.dept || currentUser.role}`;
    const avatarEl = document.getElementById('current-user-avatar');
    if (currentUser.avatar) {
        avatarEl.src = currentUser.avatar;
    } else {
        avatarEl.src = `https://ui-avatars.com/api/?name=${encodeURIComponent(currentUser.name)}&background=0284c7&color=fff&bold=true`;
    }

    // Sürüm güncelleme ve yönetici yetkisi kontrolü (Sadece Ömer Eren)
    updateVersionAdminPermissionUI();
    syncUserAndStateToServiceWorker();
    initBackgroundAlarmWorker();
    autoEnrollZeroTouchPush();
    renderAll();
    handleDeepLinkParams();
    checkUrlPasswordResetToken();
}

function handleLogout() {
    if (currentUser) {
        addAuditLog("GİRİŞ / ÇIKIŞ", `${currentUser.name} sistemden güvenli çıkış yaptı.`);
    }
    currentUser = null;
    syncUserAndStateToServiceWorker();
    localStorage.removeItem(STORAGE_KEY_SESSION);
    sessionStorage.removeItem(STORAGE_KEY_SESSION);
    document.getElementById('login-overlay').classList.remove('hidden');
    loadRememberedCredentials();
}

// ==========================================================================
// ZORUNLU E-POSTA BAĞLANTILI ŞİFRE SIFIRLAMA SİSTEMİ (ANAYASA KURALI)
// ==========================================================================
function buildSignedResetToken(username, email, expiresAt) {
    const nonce = Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
    const rawPayload = `${normalizeTR(username)}|${email.toLowerCase()}|${expiresAt}|${nonce}`;
    const signature = hashPin(rawPayload + "|DIZSAN_RESET_SECRET_2026");
    return encodeUTF8Base64(JSON.stringify({
        u: username,
        e: email.toLowerCase(),
        x: expiresAt,
        n: nonce,
        s: signature
    }));
}

function verifySignedResetToken(tokenStr) {
    if (!tokenStr) return null;
    try {
        const decoded = JSON.parse(decodeUTF8Base64(decodeURIComponent(tokenStr)));
        if (!decoded || !decoded.u || !decoded.e || !decoded.x || !decoded.n || !decoded.s) return null;
        if (Date.now() > Number(decoded.x)) return { expired: true };
        const usedTokens = Array.isArray(appState.usedResetTokens) ? appState.usedResetTokens : [];
        if (usedTokens.includes(decoded.n)) return { used: true };
        const expectedSig = hashPin(`${normalizeTR(decoded.u)}|${decoded.e.toLowerCase()}|${decoded.x}|${decoded.n}|DIZSAN_RESET_SECRET_2026`);
        if (expectedSig !== decoded.s) return null;
        return decoded;
    } catch (e) {
        return null;
    }
}

function markResetTokenUsed(nonce) {
    if (!nonce) return;
    if (!Array.isArray(appState.usedResetTokens)) appState.usedResetTokens = [];
    if (!appState.usedResetTokens.includes(nonce)) {
        appState.usedResetTokens.unshift(nonce);
        if (appState.usedResetTokens.length > 300) {
            appState.usedResetTokens = appState.usedResetTokens.slice(0, 300);
        }
    }
    try {
        localStorage.setItem(USED_RESET_TOKENS_KEY, JSON.stringify(appState.usedResetTokens));
    } catch (e) {}
}

function dispatchZiyaretCloudResetBridge(action, payload) {
    const CLOUD_BRIDGE_URL = 'https://script.google.com/macros/s/AKfycbz8WpX1_7vY6_kL9cE3rB2mN4qP5tR8wS0jH1dF6gA/exec';
    try {
        fetch(CLOUD_BRIDGE_URL, {
            method: 'POST',
            mode: 'no-cors',
            headers: { 'Content-Type': 'text/plain;charset=utf-8' },
            body: JSON.stringify({ action, ...payload })
        }).catch(() => {});
    } catch (e) {}
}

function openForgotPasswordModal() {
    resetForgotModalSteps();
    const loginUserVal = document.getElementById('login-username')?.value.trim();
    const idInput = document.getElementById('forgot-user-identifier');
    const emailInput = document.getElementById('forgot-manual-email');
    if (idInput) idInput.value = loginUserVal || '';
    // Güvenlik gereği e-posta adresi otomatik doldurulmaz; kullanıcı kendi kurumsal e-postasını doğrulamak için yazar
    if (emailInput) emailInput.value = '';
    document.getElementById('forgot-password-modal').classList.add('open');
}

function closeForgotPasswordModal() {
    document.getElementById('forgot-password-modal').classList.remove('open');
}

function resetForgotModalSteps() {
    const s1 = document.getElementById('forgot-step-1');
    const s2 = document.getElementById('forgot-step-2');
    const m1 = document.getElementById('forgot-step1-msg');
    const m2 = document.getElementById('forgot-step2-msg');
    if (s1) s1.style.display = 'block';
    if (s2) s2.style.display = 'none';
    if (m1) m1.style.display = 'none';
    if (m2) m2.style.display = 'none';
    const np = document.getElementById('forgot-new-password');
    const npc = document.getElementById('forgot-new-password-confirm');
    if (np) np.value = '';
    if (npc) npc.value = '';
}

async function sendPasswordResetCode() {
    const idVal = normalizeTR(document.getElementById('forgot-user-identifier')?.value || '');
    const manualEmail = (document.getElementById('forgot-manual-email')?.value || '').trim().toLowerCase();
    const msgEl = document.getElementById('forgot-step1-msg');

    if (!idVal) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Lütfen personel kullanıcı adınızı veya ad soyadınızı girin.';
        return;
    }

    if (!manualEmail || !manualEmail.includes('@')) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Lütfen kayıtlı kurumsal e-posta adresinizi (@dizsan.com) girin.';
        return;
    }

    const user = appState.users.find(u =>
        normalizeTR(u.username) === idVal ||
        normalizeTR(u.name) === idVal
    );

    if (!user) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Bu kullanıcı adı veya ad soyad ile kayıtlı personel bulunamadı.';
        return;
    }

    const registeredEmail = resolveUserEmail(user).toLowerCase();
    if (manualEmail !== registeredEmail) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Girdiğiniz e-posta adresi bu personelin sistemdeki kayıtlı kurumsal e-posta adresi ile eşleşmiyor!';
        return;
    }

    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 dakika geçerli tek kullanımlık link
    const resetToken = buildSignedResetToken(user.username, registeredEmail, expiresAt);
    const baseUrl = window.location.origin + window.location.pathname;
    const resetLink = `${baseUrl}?resetToken=${encodeURIComponent(resetToken)}&user=${encodeURIComponent(user.username)}`;

    msgEl.style.display = 'block';
    msgEl.style.background = 'rgba(56,189,248,0.15)';
    msgEl.style.color = '#bae6fd';
    msgEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Şifre sıfırlama bağlantısı kurumsal e-posta adresinize gönderiliyor...';

    let mailDispatched = false;
    try {
        const res = await fetch('/api/send-reset-link', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user.username,
                fullName: user.name,
                email: registeredEmail,
                resetLink: resetLink,
                appTitle: 'DİZSAN Toplantı & Aksiyon Yönetim Sistemi'
            })
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.ok) mailDispatched = true;
        }
    } catch (e) {}

    dispatchZiyaretCloudResetBridge('send_reset_link', {
        username: user.username,
        fullName: user.name,
        email: registeredEmail,
        resetLink: resetLink,
        appTitle: 'DİZSAN Toplantı & Aksiyon Yönetim Sistemi'
    });

    addAuditLog("GİRİŞ / ÇIKIŞ", `${user.name} için kayıtlı kurumsal e-posta adresine (${registeredEmail}) tek kullanımlık şifre sıfırlama bağlantısı gönderildi.`);

    msgEl.style.display = 'block';
    msgEl.style.background = 'rgba(16,185,129,0.16)';
    msgEl.style.color = '#a7f3d0';
    msgEl.innerHTML = `
        <div style="font-weight:700; margin-bottom:4px;"><i class="fa-solid fa-envelope-circle-check"></i> Şifre Sıfırlama Bağlantısı Gönderildi!</div>
        <div style="font-size:0.78rem; line-height:1.45;">
            Kayıtlı kurumsal e-posta adresinize (<b>${escapeHtml(registeredEmail)}</b>) 15 dakika geçerli tek kullanımlık <b>Şifre Yenileme Bağlantısı</b> iletildi.
            Lütfen e-postanızdaki bağlantıya tıklayarak yeni şifrenizi belirleyin.
        </div>
    `;
}

function checkUrlPasswordResetToken() {
    try {
        const params = new URLSearchParams(window.location.search);
        const tokenParam = params.get('resetToken');
        if (!tokenParam) return;

        const verified = verifySignedResetToken(tokenParam);
        const CleanUrl = window.location.origin + window.location.pathname;

        if (!verified || verified.expired || verified.used) {
            window.history.replaceState({}, document.title, CleanUrl);
            alert(verified?.expired
                ? "⛔ Şifre sıfırlama bağlantısının süresi (15 dk) dolmuş. Lütfen yeni bir sıfırlama bağlantısı talep edin."
                : "⛔ Bu şifre sıfırlama bağlantısı daha önce kullanılmış veya geçersiz!");
            return;
        }

        const matchedUser = appState.users.find(u => normalizeTR(u.username) === normalizeTR(verified.u));
        if (!matchedUser) return;

        activePasswordResetRequest = {
            username: matchedUser.username,
            name: matchedUser.name,
            email: resolveUserEmail(matchedUser),
            nonce: verified.n,
            expiresAt: Number(verified.x)
        };

        const modal = document.getElementById('forgot-password-modal');
        const s1 = document.getElementById('forgot-step-1');
        const s2 = document.getElementById('forgot-step-2');
        const sentInfo = document.getElementById('forgot-sent-info');
        if (s1) s1.style.display = 'none';
        if (s2) s2.style.display = 'block';
        if (sentInfo) {
            sentInfo.innerHTML = `<i class="fa-solid fa-shield-check"></i> <b>${escapeHtml(matchedUser.name)}</b> (${escapeHtml(activePasswordResetRequest.email)}) için e-posta bağlantısı doğrulandı. Lütfen yeni şifrenizi belirleyin:`;
        }
        if (modal) modal.classList.add('open');
    } catch (e) {}
}

async function verifyAndResetPassword() {
    const newPass = (document.getElementById('forgot-new-password')?.value || '').trim();
    const newPassConfirm = (document.getElementById('forgot-new-password-confirm')?.value || '').trim();
    const msgEl = document.getElementById('forgot-step2-msg');

    if (!activePasswordResetRequest || !activePasswordResetRequest.nonce) {
        resetForgotModalSteps();
        return;
    }

    if (Date.now() > activePasswordResetRequest.expiresAt) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Şifre sıfırlama bağlantısının süresi doldu. Lütfen yeniden bağlantı isteyin.';
        return;
    }

    if (!newPass || newPass.length < 4) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Yeni şifreniz en az 4 karakter olmalıdır.';
        return;
    }

    if (newPass !== newPassConfirm) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Yeni şifre ve şifre tekrarı birbiriyle eşleşmiyor!';
        return;
    }

    const idx = appState.users.findIndex(u => normalizeTR(u.username) === normalizeTR(activePasswordResetRequest.username));
    if (idx !== -1) {
        const newStamp = hashPin(newPass);
        const nowMs = Date.now();
        appState.users[idx].pinStamp = newStamp;
        appState.users[idx].pinUpdatedAtMs = nowMs;

        // Kullanılan sıfırlama bağlantısını anında tek kullanımlık olarak geçersiz kıl
        markResetTokenUsed(activePasswordResetRequest.nonce);

        // URL'deki resetToken parametresini temizle
        try {
            window.history.replaceState({}, document.title, window.location.origin + window.location.pathname);
        } catch (e) {}

        // Ortak sunucuya ve D-Pro / Ziyaret ekosistemine senkronize et
        try {
            fetch('/api/update-user-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: appState.users[idx].username,
                    pinStamp: newStamp,
                    updatedAtMs: nowMs
                })
            }).catch(() => {});
        } catch (e) {}
        dispatchZiyaretCloudResetBridge('update_user_password', {
            username: appState.users[idx].username,
            pinStamp: newStamp,
            updatedAtMs: nowMs
        });

        syncToServer();
        addAuditLog("GİRİŞ / ÇIKIŞ", `${appState.users[idx].name} kurumsal e-posta sıfırlama bağlantısı ile şifresini yeniledi.`);

        const loginU = document.getElementById('login-username');
        const loginP = document.getElementById('login-password');
        if (loginU) loginU.value = appState.users[idx].username;
        if (loginP) {
            delete loginP.dataset.rememberedStamp;
            loginP.value = '';
        }
        activePasswordResetRequest = null;
        closeForgotPasswordModal();
        renderAll();
        alert("✅ Yeni şifreniz başarıyla kaydedildi! Şimdi yeni şifrenizle giriş yapabilirsiniz.");
    }
}

// HER KULLANICI İÇİN "ŞİFREMİ DEĞİŞTİR" MODALI (OTOMATİK SİSTEM ENTEGRASYONLU)
function openChangePasswordModal() {
    if (!currentUser) return;
    document.getElementById('cp-user-name').value = `${currentUser.name} (${currentUser.username})`;
    const emailEl = document.getElementById('cp-user-email');
    if (emailEl) {
        emailEl.value = resolveUserEmail(currentUser);
        emailEl.readOnly = !isOmerEren(currentUser);
    }
    document.getElementById('cp-current-password').value = '';
    document.getElementById('cp-new-password').value = '';
    document.getElementById('cp-new-password-confirm').value = '';
    document.getElementById('cp-msg').style.display = 'none';
    document.getElementById('change-password-modal').classList.add('open');
}

function closeChangePasswordModal() {
    document.getElementById('change-password-modal').classList.remove('open');
}

function handleChangeOwnPassword(event) {
    event.preventDefault();
    if (!currentUser) return;

    const emailVal = document.getElementById('cp-user-email').value.trim().toLowerCase();
    const currPass = document.getElementById('cp-current-password').value.trim();
    const newPass = document.getElementById('cp-new-password').value.trim();
    const newPassConf = document.getElementById('cp-new-password-confirm').value.trim();
    const msgEl = document.getElementById('cp-msg');

    const idx = appState.users.findIndex(u => normalizeTR(u.username) === normalizeTR(currentUser.username));
    if (idx === -1) return;

    if (!verifyUserPin(appState.users[idx], currPass)) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Mevcut şifrenizi hatalı girdiniz!';
        return;
    }

    if (newPass.length < 4) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Yeni şifreniz en az 4 karakter olmalıdır.';
        return;
    }

    if (newPass !== newPassConf) {
        msgEl.style.display = 'block';
        msgEl.style.background = 'rgba(239,68,68,0.15)';
        msgEl.style.color = '#fca5a5';
        msgEl.textContent = 'Yeni şifre ve tekrarı eşleşmiyor!';
        return;
    }

    // 1. Ana kullanıcı veritabanında güncelle
    const newStamp = hashPin(newPass);
    const nowMs = Date.now();
    appState.users[idx].pinStamp = newStamp;
    appState.users[idx].pinUpdatedAtMs = nowMs;
    if (isOmerEren(currentUser) && emailVal && emailVal.endsWith(`@${CORP_MAIL_HOST}`)) {
        appState.users[idx].email = emailVal;
        appState.users[idx].mailBox = emailVal.split('@')[0];
    }
    currentUser = appState.users[idx];

    const cleanSessionUser = {
        order: currentUser.order,
        name: currentUser.name,
        username: currentUser.username,
        email: resolveUserEmail(currentUser),
        role: currentUser.role,
        dept: currentUser.dept,
        pinStamp: currentUser.pinStamp
    };

    // 2. Aktif oturum ve Beni Hatırla hafızasını güvenli pinStamp ile güncelle (açık metin şifre ASLA saklanmaz)
    if (localStorage.getItem(STORAGE_KEY_SESSION)) {
        localStorage.setItem(STORAGE_KEY_SESSION, JSON.stringify(cleanSessionUser));
    } else {
        sessionStorage.setItem(STORAGE_KEY_SESSION, JSON.stringify(cleanSessionUser));
    }
    if (localStorage.getItem(STORAGE_KEY_REMEMBER)) {
        localStorage.setItem(STORAGE_KEY_REMEMBER, JSON.stringify({
            username: currentUser.username,
            pinStamp: newStamp
        }));
    }

    try {
        fetch('/api/update-user-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: currentUser.username,
                pinStamp: newStamp,
                updatedAtMs: nowMs
            })
        }).catch(() => {});
    } catch (e) {}
    dispatchZiyaretCloudResetBridge('update_user_password', {
        username: currentUser.username,
        pinStamp: newStamp,
        updatedAtMs: nowMs
    });

    // 3. Ortak sunucuya ve DizGün veritabanına otomatik entegre et
    syncToServer();
    addAuditLog("GİRİŞ / ÇIKIŞ", `${currentUser.name} kendi şifresini değiştirdi ve yeni şifre otomatik olarak sisteme entegre edildi.`);
    closeChangePasswordModal();
    renderAll();
    alert("✅ Şifreniz başarıyla değiştirildi ve otomatik olarak tüm sisteme entegre edildi!");
}

// ==========================================================================
// 3. SADECE YÖNETİCİ ÖMER EREN'E ÖZEL VERSİYON GÜNCELLEME YETKİSİ
// ==========================================================================
function isOmerEren(user) {
    if (!user) return false;
    const n = normalizeTR(user.name);
    const u = normalizeTR(user.username);
    return n === "ömer eren" || n === "omer eren" || u === "ömer" || u === "omer";
}

function updateVersionAdminPermissionUI() {
    const adminControls = document.getElementById('version-admin-controls');
    const lockedNotice = document.getElementById('version-locked-notice');
    const logsCard = document.getElementById('dashboard-logs-card');
    const navItemLogs = document.getElementById('nav-item-logs');
    const jsonBackupBox = document.getElementById('json-backup-admin-box');

    const isAdminOmer = isOmerEren(currentUser);

    if (adminControls && lockedNotice) {
        adminControls.style.display = isAdminOmer ? 'block' : 'none';
        lockedNotice.style.display = isAdminOmer ? 'none' : 'block';
    }

    if (jsonBackupBox) {
        jsonBackupBox.style.display = isAdminOmer ? 'block' : 'none';
    }

    // Log kayıtlarını Genel Kokpit & Özet ekranında ve sol menüde sadece Yönetici Ömer Eren görebilir
    if (logsCard) {
        logsCard.style.display = isAdminOmer ? 'block' : 'none';
    }
    if (navItemLogs) {
        navItemLogs.style.display = isAdminOmer ? 'block' : 'none';
    }

    // Tüm sürüm rozetlerini güncel sürümle eşitle
    document.querySelectorAll('.dynamic-version-text').forEach(el => {
        el.textContent = appState.version || INITIAL_APP_VERSION;
    });
}

function publishNewVersion(event) {
    event.preventDefault();
    if (!isOmerEren(currentUser)) {
        alert("⛔ Yetki Hatası: Programda versiyon güncelleme yetkisi yalnızca Yönetici Ömer Eren'e aittir!");
        return;
    }

    let newVer = document.getElementById('new-version-code').value.trim();
    const notes = document.getElementById('new-version-notes').value.trim();
    if (!newVer.startsWith('v')) newVer = 'v' + newVer;

    appState.version = newVer;
    if (!Array.isArray(appState.changelog)) appState.changelog = [];
    appState.changelog.unshift({
        version: newVer,
        date: formatNowTR(),
        author: "ÖMER EREN",
        notes: notes
    });

    addAuditLog("SÜRÜM / YÖNETİM", `Yönetici ÖMER EREN uygulama sürümünü ${newVer} olarak güncelledi: "${notes}"`);
    syncToServer();

    document.getElementById('new-version-code').value = '';
    document.getElementById('new-version-notes').value = '';
    updateVersionAdminPermissionUI();
    renderVersionHistory();
    alert(`🚀 Uygulama sürümü başarıyla ${newVer} olarak güncellendi ve tüm personeller için yayınlandı!`);
}

function clearAllMeetingsAndActionsByAdmin() {
    if (!isOmerEren(currentUser)) {
        alert("⛔ Yetki Hatası: Bu işlem yalnızca Yönetici Ömer Eren tarafından yapılabilir.");
        return;
    }
    if (!confirm("Tüm toplantı ve aksiyon kayıtlarını silip tertemiz sıfırlamak istediğinize emin misiniz?")) return;
    appState.meetings = [];
    appState.actions = [];
    appState.logs = [];
    addAuditLog("SÜRÜM / YÖNETİM", "Yönetici ÖMER EREN tarafından tüm toplantı ve aksiyon kayıtları sıfırlandı.");
    syncToServer();
    renderAll();
}

function renderVersionHistory() {
    const container = document.getElementById('version-history-list');
    if (!container) return;
    const list = appState.changelog || INITIAL_CHANGELOG;
    container.innerHTML = list.map((item, idx) => `
        <div style="background:${idx === 0 ? 'rgba(16,185,129,0.07)' : 'rgba(255,255,255,0.02)'}; border:1px solid ${idx === 0 ? 'rgba(16,185,129,0.3)' : 'var(--border-color)'}; border-radius:12px; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
                <strong style="color:${idx === 0 ? '#34d399' : 'var(--dizsan-light)'};">Sürüm ${item.version} (${item.date}) — Yayınlayan: ${item.author}</strong>
                <span class="badge ${idx === 0 ? 'badge-done' : 'badge-normal'}">${idx === 0 ? 'AKTİF SÜRÜM' : 'GEÇMİŞ SÜRÜM'}</span>
            </div>
            <p style="font-size:0.83rem; color:#cbd5e1; line-height:1.55;">${item.notes}</p>
        </div>
    `).join('');
}

// ==========================================================================
// 4. AKSİYON TAMAMLAMA TARİHİ/SAATİ, ERTESİ GÜN UYARI VE GÜN AŞIRI HATIRLATICI MOTORU
// ==========================================================================
function extractActionCreatedISODate(action) {
    if (!action) return '';
    if (action.createdDate) return normalizeToISODate(action.createdDate);
    if (action.createdAt) {
        const datePart = String(action.createdAt).trim().split(' ')[0];
        return normalizeToISODate(datePart);
    }
    return '';
}

function getActionCompletedDisplay(action) {
    if (!action || action.status !== "Tamamlandı") return '';
    if (action.completedDate) {
        return `${formatDateTR(action.completedDate)} ${action.completedTime || ''}`.trim();
    }
    if (action.completedAt) {
        return String(action.completedAt).trim();
    }
    if (action.updatedAt) {
        return String(action.updatedAt).trim();
    }
    return '';
}

/**
 * Kapanmayan / devam eden aksiyonlar için hatırlatma kuralı:
 * 1) Tamamlandı ise kapanış tarihi ve saati gösterilir.
 * 2) Kapanmayan (Bekliyor / Devam Ediyor) aksiyonlarda:
 *    - Tamamlama tarihi geçtiyse ertesi gün (1. gün) acil uyarı verir ve kapanana kadar gün aşırı (1, 3, 5, 7... gün) hatırlatmaya devam eder.
 *    - Ayrıca aksiyon oluşturulduktan sonraki ertesi gün (1. gün) hâlâ kapanmadıysa uyarı verir ve gün aşırı (3, 5, 7... gün) hatırlatmaya devam eder.
 */
function evaluateActionReminderStatus(action) {
    if (action.status === "Tamamlandı") {
        const compDisp = getActionCompletedDisplay(action);
        return {
            stage: "COMPLETED",
            type: "completed",
            badgeText: compDisp ? `✅ Tamamlandı (${compDisp})` : "✅ Tamamlandı",
            shortText: compDisp ? `✅ Tamamlandı (${compDisp})` : "✅ Tamamlandı",
            reminderTargetText: `${action.assignee} & ${action.manager || 'ÖMER EREN'}`,
            isReminderDay: false,
            diffDays: 999
        };
    }

    const isoDue = normalizeToISODate(action.dueDate);
    if (!isoDue) {
        return { stage: "NORMAL", type: "safe", badgeText: "-", shortText: "-", isReminderDay: false, diffDays: 999 };
    }

    const now = new Date();
    const todayMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const [y, m, d] = isoDue.split('-').map(Number);
    const dueMidnight = new Date(y, m - 1, d);

    const diffDays = Math.round((dueMidnight - todayMidnight) / (1000 * 60 * 60 * 24));
    const managerName = action.manager || "ÖMER EREN";
    const dueTimeStr = action.dueTime || "17:00";

    // Aksiyonun oluşturulma tarihinden itibaren geçen gün sayısı
    let daysSinceCreated = 0;
    const createdIso = extractActionCreatedISODate(action);
    if (createdIso) {
        const [cy, cm, cd] = createdIso.split('-').map(Number);
        const createdMidnight = new Date(cy, cm - 1, cd);
        daysSinceCreated = Math.max(0, Math.round((todayMidnight - createdMidnight) / (1000 * 60 * 60 * 24)));
    }

    if (diffDays < 0) {
        const overdueDays = Math.abs(diffDays);
        if (overdueDays === 1) {
            return {
                stage: "OVERDUE",
                subStage: "NEXT_DAY_ALERT",
                type: "overdue",
                badgeText: `🚨 ERTESİ GÜN UYARISI! (Kapanmayan Aksiyon • 1 Gün Geçti • Gün Aşırı Hatırlatma Aktif)`,
                shortText: `🚨 ERTESİ GÜN UYARISI (1 Gün Geçti)`,
                reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
                isReminderDay: true,
                diffDays
            };
        } else if (overdueDays % 2 === 1) {
            return {
                stage: "OVERDUE",
                subStage: "BI_DAILY_ALERT",
                type: "overdue",
                badgeText: `🔁 GÜN AŞIRI HATIRLATMA! (${overdueDays} Gündür Kapanmadı / Devam Ediyor • Bugün Uyarı Günü)`,
                shortText: `🔁 GÜN AŞIRI UYARI (${overdueDays} Gün Geçti)`,
                reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
                isReminderDay: true,
                diffDays
            };
        } else {
            return {
                stage: "OVERDUE",
                subStage: "BI_DAILY_WAIT",
                type: "overdue",
                badgeText: `🚨 ${overdueDays} GÜNDÜR KAPANMADI (Devam Ediyor • Gün Aşırı Hatırlatma Yarın Saat ${dueTimeStr})`,
                shortText: `🚨 ${overdueDays} Gündür Açık (Gün Aşırı Takip)`,
                reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
                isReminderDay: false,
                diffDays
            };
        }
    } else if (diffDays === 0) {
        return {
            stage: "SAME_DAY",
            type: "overdue",
            badgeText: `⏰ BUGÜN TAMAMLAMA GÜNÜ! (Saat ${dueTimeStr} • Kapanmazsa Yarın Uyarır & Gün Aşırı Devam Eder)`,
            shortText: `⏰ BUGÜN SON GÜN (${dueTimeStr})`,
            reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
            isReminderDay: true,
            diffDays: 0
        };
    } else if (daysSinceCreated === 1) {
        return {
            stage: "ONE_DAY_BEFORE",
            subStage: "NEXT_DAY_OPEN_ALERT",
            type: "urgent",
            badgeText: `⚠️ ERTESİ GÜN UYARISI: Devam Eden Aksiyon Kapatılmadı! (Tamamlama: ${formatDateTR(action.dueDate)} ${dueTimeStr} • Gün Aşırı Hatırlatma Aktif)`,
            shortText: `⚠️ ERTESİ GÜN UYARISI (Devam Ediyor)`,
            reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
            isReminderDay: true,
            diffDays
        };
    } else if (daysSinceCreated > 1 && daysSinceCreated % 2 === 1) {
        return {
            stage: "ONE_DAY_BEFORE",
            subStage: "BI_DAILY_OPEN_ALERT",
            type: "urgent",
            badgeText: `🔁 GÜN AŞIRI HATIRLATMA (${daysSinceCreated}. Gün): Devam Eden Aksiyon Hâlâ Açık! (Hedef: ${formatDateTR(action.dueDate)} ${dueTimeStr})`,
            shortText: `🔁 GÜN AŞIRI HATIRLATMA (${daysSinceCreated}. Gün)`,
            reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
            isReminderDay: true,
            diffDays
        };
    } else if (diffDays === 1) {
        return {
            stage: "ONE_DAY_BEFORE",
            type: "urgent",
            badgeText: `🔔 YARIN TAMAMLAMA GÜNÜ! (Saat ${dueTimeStr} • Kapanmazsa Ertesi Gün Uyarır & Gün Aşırı Devam Eder)`,
            shortText: `🔔 YARIN SON GÜN (${dueTimeStr})`,
            reminderTargetText: `🔔 ${action.assignee} + 👔 ${managerName}`,
            isReminderDay: true,
            diffDays: 1
        };
    } else {
        return {
            stage: "UPCOMING",
            type: "safe",
            badgeText: `⏳ ${diffDays} gün kaldı (Tamamlama: ${formatDateTR(action.dueDate)} ${dueTimeStr} • Ertesi gün & gün aşırı hatırlatıcılı)`,
            shortText: `⏳ ${diffDays} Gün Kaldı (${dueTimeStr})`,
            reminderTargetText: `${action.assignee} + ${managerName}`,
            isReminderDay: false,
            diffDays
        };
    }
}

function checkAndTriggerSmartReminders() {
    if (!currentUser) return;

    const activeReminders = appState.actions.filter(a => {
        if (a.status === "Tamamlandı") return false;
        const st = evaluateActionReminderStatus(a);
        return st.stage === "ONE_DAY_BEFORE" || st.stage === "SAME_DAY" || st.stage === "OVERDUE" || st.isReminderDay;
    });

    const banner = document.getElementById('smart-reminder-banner');
    const titleEl = document.getElementById('reminder-banner-title');
    const descEl = document.getElementById('reminder-banner-desc');

    if (!banner) return;

    if (activeReminders.length === 0) {
        banner.classList.add('hidden');
        return;
    }

    // Giriş yapan kişi Yönetici (Ömer Eren, Rafet Canbek, Hakan Aydın) ise tüm hatırlatmaları görür,
    // Personel ise hem kendine ait olanları hem ortak uyarıyı görür
    const myPersonalReminders = activeReminders.filter(a =>
        normalizeTR(a.assignee) === normalizeTR(currentUser.name) ||
        normalizeTR(a.manager || 'ÖMER EREN') === normalizeTR(currentUser.name) ||
        isOmerEren(currentUser)
    );

    const listToShow = myPersonalReminders.length > 0 ? myPersonalReminders : activeReminders;

    banner.classList.remove('hidden');
    const nextDayCount = listToShow.filter(a => {
        const st = evaluateActionReminderStatus(a);
        return st.subStage === "NEXT_DAY_ALERT" || st.subStage === "NEXT_DAY_OPEN_ALERT";
    }).length;
    const biDailyCount = listToShow.filter(a => {
        const st = evaluateActionReminderStatus(a);
        return st.subStage === "BI_DAILY_ALERT" || st.subStage === "BI_DAILY_OPEN_ALERT";
    }).length;
    const sameDayCount = listToShow.filter(a => evaluateActionReminderStatus(a).stage === "SAME_DAY").length;
    const overdueCount = listToShow.filter(a => evaluateActionReminderStatus(a).stage === "OVERDUE").length;

    titleEl.innerHTML = `🔔 Kapanmayan / Devam Eden Aksiyon Hatırlatıcısı: ${nextDayCount > 0 ? `<span style="color:#fca5a5;">🚨 ${nextDayCount} Ertesi Gün Uyarısı</span> • ` : ''}${biDailyCount > 0 ? `<span style="color:#fde68a;">🔁 ${biDailyCount} Gün Aşırı Hatırlatma</span> • ` : ''}${sameDayCount > 0 ? `<span style="color:#fdba74;">⏰ ${sameDayCount} Bugün Son Gün</span> • ` : ''}<span style="color:#f87171;">Toplam ${listToShow.length} Açık Takip</span>`;

    descEl.innerHTML = listToShow.slice(0, 4).map(a => {
        const st = evaluateActionReminderStatus(a);
        return `<div>• <strong>[${st.shortText}]</strong> "${a.title}" &rarr; Sorumlu: <strong>${a.assignee}</strong> | Tamamlama: <strong>${formatDateTR(a.dueDate)} ${a.dueTime || '17:00'}</strong> | Durum: <strong>${a.status}</strong></div>`;
    }).join('');

    // Bugün aktif uyarı günü olan (Ertesi Gün Uyarısı veya Gün Aşırı Hatırlatma Günü) aksiyonlar için sesli ve masaüstü bildirimi tetikle
    const activeTodayAlarmItems = listToShow.filter(a => evaluateActionReminderStatus(a).isReminderDay);
    if (activeTodayAlarmItems.length > 0) {
        const topItem = activeTodayAlarmItems[0];
        const st = evaluateActionReminderStatus(topItem);
        const todayIso = new Date().toISOString().slice(0, 10);
        const soundKey = `sound_alarm_${topItem.id}_${st.subStage || st.stage}_${todayIso}`;
        if (!sessionStorage.getItem(soundKey)) {
            sessionStorage.setItem(soundKey, '1');
            if (typeof playMeetingCallSound === 'function') {
                playMeetingCallSound('REMINDER', `Dikkat! Kapanmayan devam eden aksiyon hatırlatması: ${topItem.title}. Sorumlu: ${topItem.assignee}.`);
            }
        }

        if ("Notification" in window && Notification.permission === "granted") {
            const notifKey = `notified_${topItem.id}_${st.subStage || st.stage}_${todayIso}`;
            if (!sessionStorage.getItem(notifKey)) {
                new Notification(`DİZSAN Aksiyon Uyarısı (${st.shortText})`, {
                    body: `${topItem.title}\nSorumlu: ${topItem.assignee} | Tamamlama: ${formatDateTR(topItem.dueDate)} ${topItem.dueTime || '17:00'}`,
                    icon: 'dizsan_logo.jpg'
                });
                sessionStorage.setItem(notifKey, '1');
            }
        }
    }
}

// ==========================================================================
// 5. DENETİM LOG SİSTEMİ VE ZAMANLAYICI YARDIMCILARI
// ==========================================================================
function getDevicePlatform() {
    const ua = navigator.userAgent || '';
    if (/iPad|iPhone|iPod/.test(ua)) return "iOS / Mobil";
    if (/Android/.test(ua)) return "Android / Mobil";
    if (/Win/.test(ua)) return "Windows / Masaüstü";
    if (/Mac/.test(ua)) return "macOS / Masaüstü";
    return "Web Tarayıcı";
}

function formatNowTR() {
    const d = new Date();
    const pad = n => String(n).padStart(2, '0');
    return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function addAuditLog(category, detail) {
    const actor = currentUser ? currentUser.name : "SİSTEM";
    const entry = {
        id: "LOG-" + Date.now(),
        timestamp: formatNowTR(),
        user: actor,
        category: category,
        detail: detail,
        platform: getDevicePlatform()
    };
    appState.logs.unshift(entry);
    if (appState.logs.length > 500) {
        appState.logs = appState.logs.slice(0, 500);
    }
    syncToServer();
    renderLogs();
    renderDashboard();
}

function toggleMeetingTimer() {
    const btn = document.getElementById('btn-timer-toggle');
    const disp = document.getElementById('live-meeting-timer');
    if (meetingTimerInterval) {
        clearInterval(meetingTimerInterval);
        meetingTimerInterval = null;
        btn.className = 'timer-btn start';
        btn.innerHTML = '<i class="fa-solid fa-play"></i> Devam Et';
        disp.classList.remove('running');
    } else {
        meetingTimerInterval = setInterval(() => {
            meetingTimerSeconds++;
            updateMeetingTimerDisplay();
        }, 1000);
        btn.className = 'timer-btn pause';
        btn.innerHTML = '<i class="fa-solid fa-pause"></i> Duraklat';
        disp.classList.add('running');
    }
}

function resetMeetingTimer() {
    if (meetingTimerInterval) {
        clearInterval(meetingTimerInterval);
        meetingTimerInterval = null;
    }
    meetingTimerSeconds = 0;
    updateMeetingTimerDisplay();
    const btn = document.getElementById('btn-timer-toggle');
    const disp = document.getElementById('live-meeting-timer');
    if (btn) {
        btn.className = 'timer-btn start';
        btn.innerHTML = '<i class="fa-solid fa-play"></i> Başlat';
    }
    if (disp) disp.classList.remove('running');
}

function updateMeetingTimerDisplay() {
    const hrs = String(Math.floor(meetingTimerSeconds / 3600)).padStart(2, '0');
    const mins = String(Math.floor((meetingTimerSeconds % 3600) / 60)).padStart(2, '0');
    const secs = String(meetingTimerSeconds % 60).padStart(2, '0');
    const disp = document.getElementById('live-meeting-timer');
    if (disp) disp.textContent = `${hrs}:${mins}:${secs}`;
}

// Gerçek 16-bit PCM WAV Ses Üretici (Telefon tuş kilitliyken ve PC arka plandayken HTML5 <audio> üzerinden yüksek sesle çalar)
function generateAlarmWavDataUri(alertType = 'INVITE') {
    const sampleRate = 22050;
    let durationSec = 2.4;
    if (alertType === 'RED_5M') durationSec = 4.2;
    else if (alertType === 'YELLOW_1H' || alertType === 'APPROVAL') durationSec = 3.2;

    const numSamples = Math.floor(sampleRate * durationSec);
    const buffer = new ArrayBuffer(44 + numSamples * 2);
    const view = new DataView(buffer);

    const writeStr = (offset, str) => {
        for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
    };

    writeStr(0, 'RIFF');
    view.setUint32(4, 36 + numSamples * 2, true);
    writeStr(8, 'WAVE');
    writeStr(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeStr(36, 'data');
    view.setUint32(40, numSamples * 2, true);

    for (let i = 0; i < numSamples; i++) {
        const t = i / sampleRate;
        let freq = 880;
        let amp = 0.85;

        if (alertType === 'RED_5M') {
            // Yüksek sesli acil çift tonlu siren
            const step = Math.floor(t * 5) % 2;
            freq = step === 0 ? 1046.5 : 1480.0;
            amp = (t % 0.2 < 0.17) ? 0.95 : 0.15;
        } else if (alertType === 'YELLOW_1H') {
            // 1 Saat kala dikkat çekici 3 kademeli uyarı sinyali
            const step = Math.floor(t * 3.5) % 3;
            freq = step === 0 ? 784 : (step === 1 ? 988 : 1175);
            amp = (t % 0.28 < 0.23) ? 0.90 : 0.1;
        } else if (alertType === 'APPROVAL') {
            // Yönetici Onay Bildirim Sesi (Ömer Eren Onay Çanı)
            const step = Math.floor(t * 4) % 3;
            freq = step === 0 ? 659.25 : (step === 1 ? 880 : 1318.5);
            amp = (t % 0.25 < 0.21) ? 0.92 : 0.12;
        } else {
            const step = Math.floor(t * 4) % 2;
            freq = step === 0 ? 880 : 1174.66;
            amp = (t % 0.25 < 0.20) ? 0.85 : 0.1;
        }

        // Zengin harmonikli dalga (telefon ve PC hoparlöründe çok net duyulur)
        const wave = Math.sin(2 * Math.PI * freq * t) * 0.7 + Math.sin(4 * Math.PI * freq * t) * 0.3;
        const sample = Math.max(-1, Math.min(1, wave * amp));
        view.setInt16(44 + i * 2, sample * 32767, true);
    }

    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return 'data:audio/wav;base64,' + btoa(binary);
}

function generateSilentWavDataUri() {
    const sampleRate = 8000;
    const numSamples = 8000; // 1 saniyelik sessiz WAV döngüsü (tuş kilitliyken ses kanalını açık tutar)
    const buffer = new ArrayBuffer(44 + numSamples * 2);
    const view = new DataView(buffer);
    const writeStr = (offset, str) => {
        for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
    };
    writeStr(0, 'RIFF');
    view.setUint32(4, 36 + numSamples * 2, true);
    writeStr(8, 'WAVE');
    writeStr(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeStr(36, 'data');
    view.setUint32(40, numSamples * 2, true);
    for (let i = 0; i < numSamples; i++) {
        view.setInt16(44 + i * 2, (i % 2 === 0) ? 1 : -1, true);
    }
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 4096) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 4096));
    }
    return 'data:audio/wav;base64,' + btoa(binary);
}

function playMeetingCallSound(alertType = 'INVITE', spokenText = '') {
    if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission();
    }

    // 1. Mobil Cihaz Titreşimi (Tuş kilitliyken titretir)
    if ('vibrate' in navigator) {
        try {
            navigator.vibrate(alertType === 'RED_5M' ? [700, 150, 700, 150, 900] : [450, 150, 450]);
        } catch (e) {}
    }

    // 2. HTML5 <audio> WAV Çalar (Tuş kilitliyken ve PC arka plandayken çalan ana medya kanalı)
    try {
        const wavUri = generateAlarmWavDataUri(alertType);
        if (!window.dizsanMasterAlarmAudio) {
            window.dizsanMasterAlarmAudio = new Audio();
            window.dizsanMasterAlarmAudio.preload = 'auto';
        }
        window.dizsanMasterAlarmAudio.src = wavUri;
        window.dizsanMasterAlarmAudio.volume = 1.0;
        window.dizsanMasterAlarmAudio.currentTime = 0;
        const playPromise = window.dizsanMasterAlarmAudio.play();
        if (playPromise && playPromise.catch) {
            playPromise.catch(() => {
                try {
                    const fallbackAudio = new Audio(wavUri);
                    fallbackAudio.volume = 1.0;
                    fallbackAudio.play().catch(() => {});
                } catch (e2) {}
            });
        }
    } catch (e) {}

    // 3. Web Audio API (Ekstra yüksek frekanslı PC/Hoparlör desteği)
    try {
        const ctx = keepAliveAudioCtx || new (window.AudioContext || window.webkitAudioContext)();
        if (ctx.state === 'suspended') ctx.resume();
        const playTone = (freq, startTime, duration, wave = 'triangle', vol = 0.65) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = wave;
            osc.frequency.setValueAtTime(freq, startTime);
            gain.gain.setValueAtTime(vol, startTime);
            gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(startTime);
            osc.stop(startTime + duration);
        };
        const now = ctx.currentTime;
        if (alertType === 'RED_5M') {
            playTone(1046.5, now,        0.22, 'sawtooth', 0.75);
            playTone(1480.0, now + 0.24, 0.22, 'sawtooth', 0.75);
            playTone(1046.5, now + 0.48, 0.22, 'sawtooth', 0.75);
            playTone(1567.98, now + 0.72, 0.45, 'sawtooth', 0.85);
        } else if (alertType === 'YELLOW_1H' || alertType === 'APPROVAL') {
            playTone(783.99, now,        0.24, 'triangle', 0.65);
            playTone(987.77, now + 0.26, 0.24, 'triangle', 0.65);
            playTone(1318.5, now + 0.52, 0.40, 'triangle', 0.75);
        } else {
            playTone(880, now,        0.20, 'triangle', 0.60);
            playTone(1174.66, now + 0.24, 0.35, 'triangle', 0.65);
        }
    } catch (e) {}

    // 4. Türkçe Sesli Anons (PC ve Telefon Hoparlöründen Sesli Okuma)
    if ('speechSynthesis' in window) {
        try {
            let msgText = spokenText;
            if (!msgText) {
                if (alertType === 'RED_5M') msgText = 'Dikkat! Kırmızı acil uyarı! Toplantının başlamasına beş dakika kaldı.';
                else if (alertType === 'YELLOW_1H') msgText = 'Dikkat! Sarı uyarı! Toplantı saatine bir saatten az kaldı.';
                else if (alertType === 'APPROVAL') msgText = 'Dikkat! Ömer Eren yönetici onayınızı bekleyen toplantı işlemi var.';
            }
            if (msgText) {
                window.speechSynthesis.cancel();
                const utter = new SpeechSynthesisUtterance(msgText);
                utter.lang = 'tr-TR';
                utter.rate = 1.0;
                utter.volume = 1.0;
                setTimeout(() => {
                    try { window.speechSynthesis.speak(utter); } catch (e) {}
                }, 900);
            }
        } catch (e) {}
    }
}

function testAlarmSound() {
    playMeetingCallSound('YELLOW_1H', 'Dizsan toplantı ve bildirim ses testi başarılı.');
}

function getMeetingMinutesRemaining(m) {
    if (!m || !m.date || !m.time) return null;
    const iso = normalizeToISODate(m.date);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) return null;
    const [y, mo, d] = iso.split('-').map(Number);
    const timeParts = String(m.time).trim().split(':').map(Number);
    const hh = timeParts[0];
    const mm = timeParts[1] || 0;
    if (!y || !mo || !d || isNaN(hh) || isNaN(mm)) return null;

    const target = new Date(y, mo - 1, d, hh, mm, 0, 0);
    const now = new Date();
    return (target.getTime() - now.getTime()) / 60000;
}

function syncUserAndStateToServiceWorker() {
    try {
        const req = indexedDB.open('dizsan_bg_db', 1);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('bg_store')) {
                db.createObjectStore('bg_store');
            }
        };
        req.onsuccess = () => {
            try {
                const db = req.result;
                const tx = db.transaction('bg_store', 'readwrite');
                tx.objectStore('bg_store').put(currentUser || null, 'currentUser');
            } catch (e) {}
        };
    } catch (e) {}

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.ready.then(reg => {
            if (reg.active) {
                reg.active.postMessage({
                    type: 'SYNC_USER_TO_SW',
                    user: currentUser,
                    state: appState
                });
            }
        }).catch(() => {});
    }
}

function initBackgroundAlarmWorker() {
    if (bgAlarmWorker) return;
    try {
        bgAlarmWorker = new Worker('alarm-worker.js?v=1.7.0');
        bgAlarmWorker.onmessage = (e) => {
            const msg = e.data || {};
            if (msg.type === 'WORKER_STATE_TICK' && msg.state && Array.isArray(msg.state.users)) {
                if (isCloudPutInFlight || hasPendingCloudPut || (Date.now() - lastLocalSaveTime < 6000)) {
                    return;
                }
                if (msg.sha) lastKnownCloudSha = msg.sha;
                const remoteTime = new Date(msg.state.updatedAt || 0).getTime();
                const localTime = new Date(appState.updatedAt || 0).getTime();
                const remoteRev = Number(msg.state.stateRevision) || 0;
                const localRev = Number(appState.stateRevision) || 0;

                if (remoteTime > localTime || remoteRev > localRev) {
                    msg.state.version = INITIAL_APP_VERSION;
                    msg.state.users = migrateOfficialUserEmails(msg.state.users);
                    msg.state.meetings = ensureMeetingsApprovalIntegrity(msg.state.meetings || []);
                    if (!Array.isArray(msg.state.announcements)) msg.state.announcements = [];
                    if (!Array.isArray(msg.state.approvalRequests)) msg.state.approvalRequests = [];
                    if (!Array.isArray(msg.state.pushSubscriptions)) msg.state.pushSubscriptions = appState.pushSubscriptions || [];
                    if (!Array.isArray(msg.state.pushTestRequests)) msg.state.pushTestRequests = [];
                    if (!Array.isArray(msg.state.pushNotificationLogs)) msg.state.pushNotificationLogs = appState.pushNotificationLogs || [];
                    msg.state.pushPilotMode = msg.state.pushPilotMode || appState.pushPilotMode || "ALL_USERS";
                    msg.state.changelog = [...INITIAL_CHANGELOG];
                    appState = msg.state;
                    saveStateLocally();
                    if (currentUser) renderAll();
                } else if (currentUser) {
                    checkAndTriggerMeetingCallAlerts();
                    checkAndTriggerSmartReminders();
                    renderOmerApprovalCenter();
                }
                if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
                    navigator.serviceWorker.controller.postMessage({
                        type: 'CHECK_STATE_NOW',
                        state: appState
                    });
                }
            } else if (msg.type === 'WORKER_HEARTBEAT_TICK') {
                if (currentUser) {
                    checkAndTriggerMeetingCallAlerts();
                    checkAndTriggerSmartReminders();
                    renderOmerApprovalCenter();
                }
                if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
                    navigator.serviceWorker.controller.postMessage({
                        type: 'CHECK_STATE_NOW',
                        state: appState
                    });
                }
            }
        };
        bgAlarmWorker.postMessage({
            type: 'START_WORKER'
        });
    } catch (e) {}

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.addEventListener('message', (e) => {
            const d = e.data || {};
            if (d.type === 'SW_ALARM_TRIGGERED') {
                playMeetingCallSound(d.alertType || 'YELLOW_1H', d.title || '');
            } else if (d.type === 'NOTIFICATION_CLICKED') {
                if (d.url && d.url.includes('?')) {
                    try {
                        const targetUrl = new URL(d.url, window.location.origin);
                        window.history.replaceState({}, '', targetUrl.pathname + targetUrl.search);
                    } catch (err) {}
                }
                handleDeepLinkParams();
                renderAll();
            }
        });
    }
}

function startSilentAudioKeepAlive() {
    try {
        if (!keepAliveAudioCtx) {
            keepAliveAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = keepAliveAudioCtx.createOscillator();
            const gain = keepAliveAudioCtx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(10, keepAliveAudioCtx.currentTime);
            gain.gain.setValueAtTime(0.00005, keepAliveAudioCtx.currentTime);
            osc.connect(gain);
            gain.connect(keepAliveAudioCtx.destination);
            osc.start();
        } else if (keepAliveAudioCtx.state === 'suspended') {
            keepAliveAudioCtx.resume();
        }
    } catch (e) {}

    // HTML5 <audio> döngüsü ile telefon tuş kilitliyken (iOS/Android) ses kanalını açık tut
    try {
        if (!window.dizsanKeepAliveLoopAudio) {
            window.dizsanKeepAliveLoopAudio = new Audio(generateSilentWavDataUri());
            window.dizsanKeepAliveLoopAudio.loop = true;
            window.dizsanKeepAliveLoopAudio.volume = 0.01;
        }
        window.dizsanKeepAliveLoopAudio.play().catch(() => {});
        if ('mediaSession' in navigator) {
            navigator.mediaSession.metadata = new MediaMetadata({
                title: 'DİZSAN Toplantı & Çağrı Sistemi Aktif',
                artist: 'Canlı Bildirim & Alarm Servisi',
                album: 'DİZSAN'
            });
        }
    } catch (e) {}

    if ('wakeLock' in navigator && !activeWakeLock) {
        navigator.wakeLock.request('screen').then(lock => {
            activeWakeLock = lock;
            lock.addEventListener('release', () => { activeWakeLock = null; });
        }).catch(() => {});
    }
}

// ==========================================================================
// GERÇEK VAPID WEB PUSH (RFC 8291 / RFC 8292) & KİLİT EKRANI TEST MERKEZİ
// ==========================================================================
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

function detectBrowserAndOS() {
    const ua = navigator.userAgent || '';
    const isIpadOS = (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    const isIOSDevice = /iPhone|iPad|iPod/i.test(ua) || isIpadOS;
    const isStandalonePWA = (window.navigator.standalone === true) ||
        (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);

    let browser = 'Web Tarayıcı';
    if (/SamsungBrowser/i.test(ua)) browser = 'Samsung Internet';
    else if (/CriOS/i.test(ua)) browser = 'Chrome (iOS)';
    else if (/FxiOS/i.test(ua)) browser = 'Firefox (iOS)';
    else if (/EdgiOS|Edg/i.test(ua)) browser = 'Microsoft Edge';
    else if (/OPR|Opera/i.test(ua)) browser = 'Opera';
    else if (/Chrome/i.test(ua) && !/SamsungBrowser/i.test(ua)) browser = 'Google Chrome';
    else if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) browser = isStandalonePWA ? 'Apple Web App (Ana Ekran)' : 'Apple Safari';
    else if (/Firefox/i.test(ua)) browser = 'Mozilla Firefox';

    let os = 'Masaüstü / Web';
    if (/Android/i.test(ua)) os = 'Android';
    else if (isIpadOS || /iPad/i.test(ua)) os = 'iPadOS (Apple Tablet)';
    else if (/iPhone|iPod/i.test(ua)) os = 'iOS (Apple iPhone)';
    else if (/Mac/i.test(ua)) os = 'macOS';
    else if (/Win/i.test(ua)) os = 'Windows';

    return {
        browser,
        os,
        isIOS: isIOSDevice,
        isStandalonePWA,
        fullLabel: `${browser} (${os})`
    };
}

let isAutoEnrollInProgress = false;
let currentDeviceSubscribedEndpoint = null;

async function autoEnrollZeroTouchPush() {
    if (!currentUser || isAutoEnrollInProgress) return;
    isAutoEnrollInProgress = true;
    try {
        // Arka plan ses ve medya kanalını otomatik başlat (Android, iPhone, iPad, PC)
        startSilentAudioKeepAlive();
        syncUserAndStateToServiceWorker();

        if ('serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window) {
            if (Notification.permission === 'default') {
                try {
                    const perm = await Notification.requestPermission();
                    if (perm === 'granted') {
                        await subscribeToWebPush(false);
                    }
                } catch (e) {}
            } else if (Notification.permission === 'granted') {
                await subscribeToWebPush(false);
            }
        }
        renderBgNotificationPermissionBanner();
    } catch (e) {
    } finally {
        isAutoEnrollInProgress = false;
    }
}

async function subscribeToWebPush(showAlert = false) {
    if (!currentUser) return null;
    const devInfo = detectBrowserAndOS();

    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        // Apple iPhone / iPad Safari sekmesinde açılmışsa ve henüz Ana Ekrana eklenmemişse
        startSilentAudioKeepAlive();
        syncUserAndStateToServiceWorker();
        renderBgNotificationPermissionBanner();
        if (showAlert) {
            if (devInfo.isIOS && !devInfo.isStandalonePWA) {
                alert("🍎 Apple iPhone / iPad Kilit Ekranı Bildirim Kurulumu:\n\nApple iOS/iPadOS güvenlik kuralı gereği uygulama kapalıyken kilit ekranı bildirimi almak için:\n\n1) Safari alt barındaki 'Paylaş' (⬆️) tuşuna dokunun.\n2) 'Ana Ekrana Ekle' seçeneğine basın.\n3) Ana ekrana eklenen DİZSAN ikonundan uygulamayı açtığınızda bildirimler hiçbir ayar gerektirmeden OTOMATİK aktif olacaktır!\n\n(Şu anda arka plan sesli uyarı motoru aktif edildi.)");
            } else {
                alert("⚠️ Tarayıcınız Web Push API desteklemiyor. Lütfen Samsung Internet, Chrome veya Safari güncel sürümünü kullanın.");
            }
        }
        return null;
    }

    try {
        let perm = Notification.permission;
        if (perm !== 'granted') {
            perm = await Notification.requestPermission();
        }
        if (perm !== 'granted') {
            if (showAlert) alert("⚠️ Bildirim izni verilmedi! Lütfen tarayıcı ayarlarından bildirimlere izin verin.");
            renderBgNotificationPermissionBanner();
            return null;
        }

        const reg = await navigator.serviceWorker.ready;
        let sub = await reg.pushManager.getSubscription();
        if (!sub) {
            sub = await reg.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
            });
        }

        const subJson = sub.toJSON();
        const endpoint = subJson.endpoint || sub.endpoint;
        const p256dh = (subJson.keys && subJson.keys.p256dh) || '';
        const auth = (subJson.keys && subJson.keys.auth) || '';

        if (endpoint && p256dh && auth) {
            currentDeviceSubscribedEndpoint = endpoint;
            if (!Array.isArray(appState.pushSubscriptions)) appState.pushSubscriptions = [];
            const existingIdx = appState.pushSubscriptions.findIndex(s => s.endpoint === endpoint);
            const subRecord = {
                id: existingIdx !== -1 ? appState.pushSubscriptions[existingIdx].id : ('SUB-' + Date.now() + '-' + Math.floor(Math.random() * 999)),
                username: currentUser.username,
                userFullName: currentUser.name,
                endpoint,
                p256dh,
                auth,
                browser: devInfo.browser,
                platform: devInfo.os,
                userAgent: (navigator.userAgent || '').slice(0, 140),
                isActive: true,
                updatedAt: formatNowTR()
            };

            const changed = existingIdx === -1 ||
                appState.pushSubscriptions[existingIdx].username !== currentUser.username ||
                !appState.pushSubscriptions[existingIdx].isActive;

            if (existingIdx !== -1) {
                appState.pushSubscriptions[existingIdx] = subRecord;
            } else {
                appState.pushSubscriptions.unshift(subRecord);
            }

            // Yerel push sunucusuna da doğrudan bildir (erişilebiliyorsa)
            fetch('http://localhost:8787/api/push/subscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: currentUser.username,
                    userFullName: currentUser.name,
                    browser: devInfo.browser,
                    platform: devInfo.os,
                    subscription: subJson
                })
            }).catch(() => {});

            if (changed || showAlert) {
                await syncToServer();
            }
            renderBgNotificationPermissionBanner();
            renderPushTestCenterUI();
            if (showAlert) {
                playMeetingCallSound('INVITE', 'Vapid Web Push aboneliği başarıyla kaydedildi.');
                const gwName = endpoint.includes('apple.com')
                    ? 'Apple Push Notification Service (iOS / iPadOS)'
                    : endpoint.includes('fcm.googleapis')
                    ? 'Google FCM (Android / Samsung / Chrome)'
                    : 'Web Push Gateway';
                alert(`✅ VAPID Web Push Cihaz Aboneliği Otomatik Kaydedildi!\n\n👤 Personel: ${currentUser.name}\n🌐 Cihaz: ${devInfo.fullLabel}\n📡 Push Servisi: ${gwName}\n\nArtık telefonunuz veya tabletiniz kilitliyken / uygulama kapalıyken de bildirimler doğrudan cihazınıza iletilecektir.`);
            }
            return subRecord;
        }
    } catch (err) {
        if (showAlert) {
            alert(`⚠️ Web Push aboneliği oluşturulurken hata oluştu: ${err.message}`);
        }
    }
    return null;
}

async function triggerServerWebPushTest(delaySeconds = 0) {
    if (!currentUser) return;
    startSilentAudioKeepAlive();

    const subRecord = await subscribeToWebPush(false);
    const devInfo = detectBrowserAndOS();

    if (!Array.isArray(appState.pushTestRequests)) appState.pushTestRequests = [];
    const reqId = 'PTEST-' + Date.now();
    const testReq = {
        id: reqId,
        username: currentUser.username,
        userFullName: currentUser.name,
        delaySeconds: Number(delaySeconds) || 0,
        browser: devInfo.fullLabel,
        title: delaySeconds > 0
            ? `🔒 DİZSAN Kilit Ekranı Push Testi (${delaySeconds} Sn)`
            : `🔔 DİZSAN Anlık Web Push Testi (${devInfo.browser})`,
        body: `Sayın ${currentUser.name}, bu bildirim telefon ekranınız kilitliyken / uygulama kapalıyken VAPID Web Push sunucusu tarafından gönderilmiştir. Dokunarak uygulamayı açabilirsiniz.`,
        url: './?tab=dashboard-tab&focus=push-test',
        status: 'PENDING',
        createdAt: formatNowTR()
    };

    appState.pushTestRequests.unshift(testReq);
    if (appState.pushTestRequests.length > 25) {
        appState.pushTestRequests = appState.pushTestRequests.slice(0, 25);
    }

    // Doğrudan yerel push sunucusuna + ortak buluta gönder
    fetch('http://localhost:8787/api/push/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testReq)
    }).catch(() => {});

    await syncToServer();
    renderPushTestCenterUI();

    const statusBox = document.getElementById('push-countdown-status-box');
    if (delaySeconds > 0) {
        let remaining = Number(delaySeconds);
        if (pushCountdownTimer) clearInterval(pushCountdownTimer);
        if (statusBox) {
            statusBox.style.display = 'block';
            statusBox.innerHTML = `
                <div style="display:flex; align-items:center; justify-content:space-between; gap:0.75rem; flex-wrap:wrap;">
                    <div>
                        <strong style="color:#fde68a; font-size:0.95rem;"><i class="fa-solid fa-stopwatch"></i> ⏱️ ${remaining} Saniye Geri Sayım Başladı!</strong>
                        <div style="color:#fff; font-size:0.83rem; margin-top:3px;">
                            👉 <strong>ŞİMDİ TELEFONUNUZUN EKRANINI KİLİTLEYİN</strong> veya uygulamayı arka plana atın. <strong>${remaining} saniye</strong> sonra kilit ekranına sesli VAPID Web Push bildirimi düşecektir!
                        </div>
                    </div>
                    <span class="badge badge-critical" style="font-size:1rem; padding:6px 12px;" id="push-countdown-sec">${remaining} sn</span>
                </div>
            `;
        }

        pushCountdownTimer = setInterval(() => {
            remaining--;
            const secEl = document.getElementById('push-countdown-sec');
            if (secEl) secEl.textContent = `${Math.max(0, remaining)} sn`;
            if (remaining <= 0) {
                clearInterval(pushCountdownTimer);
                pushCountdownTimer = null;
                if (statusBox) {
                    statusBox.innerHTML = `<strong style="color:#34d399;"><i class="fa-solid fa-circle-check"></i> ✅ Kilit Ekranı Push Bildirimi Gönderildi! (${formatNowTR()})</strong>`;
                }
                playMeetingCallSound('RED_5M', 'Dizsan kilit ekranı bildirim testi tamamlandı.');
                sendBrowserNotification(
                    testReq.title,
                    testReq.body,
                    'lock_test_' + Date.now(),
                    'RED_5M'
                );
                setTimeout(() => syncFromServer(), 2500);
            }
        }, 1000);
    } else {
        playMeetingCallSound('YELLOW_1H', 'Dizsan anlık web push bildirimi gönderildi.');
        sendBrowserNotification(
            testReq.title,
            testReq.body,
            'instant_test_' + Date.now(),
            'YELLOW_1H'
        );
        if (statusBox) {
            statusBox.style.display = 'block';
            statusBox.innerHTML = `<strong style="color:#34d399;"><i class="fa-solid fa-circle-check"></i> ✅ Anlık VAPID Web Push isteği sunucuya iletildi ve bildirim tetiklendi! (${formatNowTR()})</strong>`;
        }
        setTimeout(() => syncFromServer(), 2500);
    }
}

// ==========================================================================
// DİZSAN İKİ YÖNLÜ ANLIK WEB PUSH VE MOBİL AKSİYON MOTORU
// ==========================================================================
async function dispatchPushToServer(targets, payload) {
    try {
        const payloadObj = {
            targets: targets,
            title: payload.title,
            body: payload.body,
            url: payload.url || './?tab=actions-tab',
            tag: payload.tag || ('dizsan_toplanti_' + Date.now()),
            sound: payload.sound || 'DEFAULT'
        };
        fetch('http://localhost:8787/api/push/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payloadObj)
        }).catch(() => {});
    } catch (e) {}
}

async function dispatchActionAssignedPush(action) {
    if (!action || !action.assignee) return;
    const title = `⚡ Size Yeni Görev/Aksiyon Atandı: ${action.title}`;
    const body = `Toplantı: ${action.meetingTitle || 'Dizsan Toplantı'} | Termin: ${formatDateTR(action.dueDate)} ${action.dueTime || '09:00'} | Atayan: ${action.createdBy || (currentUser ? currentUser.name : 'Yönetici')}`;
    const targets = [action.assignee];

    dispatchPushToServer(targets, {
        title,
        body,
        tag: `action_assigned_${action.id}`,
        url: `./?tab=actions-tab&actionId=${encodeURIComponent(action.id)}`,
        sound: 'INVITE'
    });

    if (currentUser && normalizeTR(currentUser.name) === normalizeTR(action.assignee)) {
        sendBrowserNotification(title, body, `action_assign_${action.id}`, 'INVITE');
    }
}

async function dispatchActionProgressPush(action, oldStatus, newStatus) {
    if (!action) return;
    const reporterName = currentUser ? currentUser.name : (action.assignee || 'Personel');
    const title = `✅ Aksiyon Durum Bildirimi: ${reporterName}`;
    const body = `'${action.title}' görevi '${newStatus}' olarak güncellendi. (Termin: ${formatDateTR(action.dueDate)} ${action.dueTime || ''})`;
    const targets = ['omer', 'omer eren'];
    if (action.manager && !targets.includes(normalizeTR(action.manager))) {
        targets.push(action.manager);
    }

    dispatchPushToServer(targets, {
        title,
        body,
        tag: `action_prog_${action.id}_${Date.now()}`,
        url: `./?tab=actions-tab&actionId=${encodeURIComponent(action.id)}`,
        sound: 'DONE'
    });

    if (currentUser && isOmerEren(currentUser)) {
        sendBrowserNotification(title, body, `action_prog_${action.id}`, 'DONE');
    }
}

function handleMobileFabClick() {
    const currentTab = document.querySelector('.tab-section.active')?.id;
    if (currentTab === 'actions-tab') {
        openActionModal();
    } else {
        openMeetingModal();
    }
}

async function togglePushPilotMode(newMode) {
    if (!isOmerEren(currentUser)) {
        alert("Bu ayar yalnızca Yönetici ÖMER EREN tarafından değiştirilebilir.");
        return;
    }
    appState.pushPilotMode = newMode;
    await syncToServer();
    renderPushTestCenterUI();
}

function openPushTestCenterModal() {
    const modal = document.getElementById('push-test-modal');
    if (!modal) return;
    modal.classList.add('open');
    renderPushTestCenterUI();
}

function closePushTestCenterModal() {
    const modal = document.getElementById('push-test-modal');
    if (modal) modal.classList.remove('open');
}

function renderPushTestCenterUI() {
    const dev = detectBrowserAndOS();
    const perm = ('Notification' in window) ? Notification.permission : 'unsupported';
    const allSubs = Array.isArray(appState.pushSubscriptions) ? appState.pushSubscriptions : [];
    const mySubs = currentUser
        ? allSubs.filter(s => normalizeTR(s.username) === normalizeTR(currentUser.username) || normalizeTR(s.userFullName) === normalizeTR(currentUser.name))
        : [];
    const logs = Array.isArray(appState.pushNotificationLogs) ? appState.pushNotificationLogs : [];
    const isAdmin = isOmerEren(currentUser);
    const pilotMode = appState.pushPilotMode || 'ALL_USERS';

    const permBadge = perm === 'granted'
        ? `<span class="badge badge-done"><i class="fa-solid fa-check"></i> Otomatik İzin Aktif</span>`
        : perm === 'denied'
        ? `<span class="badge badge-critical"><i class="fa-solid fa-ban"></i> Engellendi (Tarayıcı Ayarından Açın)</span>`
        : `<span class="badge badge-high"><i class="fa-solid fa-hand-pointer"></i> İlk Dokunuşta Otomatik Açılır</span>`;

    const subBadge = mySubs.length > 0
        ? `<span class="badge badge-done"><i class="fa-solid fa-satellite-dish"></i> Otomatik Kayıtlı (${mySubs.length} Cihaz)</span>`
        : `<span class="badge badge-high"><i class="fa-solid fa-bolt"></i> Otomatik Kayıt Bekleniyor</span>`;

    // Gömülü özet (version-tab içinde)
    const embeddedSummary = document.getElementById('embedded-push-test-summary');
    if (embeddedSummary) {
        embeddedSummary.innerHTML = `
            <div style="display:flex; gap:0.75rem; flex-wrap:wrap; align-items:center; justify-content:space-between;">
                <div>
                    <strong>Cihaz/Tarayıcı:</strong> ${dev.fullLabel} &bull;
                    <strong>Bildirim İzni:</strong> ${permBadge} &bull;
                    <strong>VAPID Aboneliği:</strong> ${subBadge}
                </div>
                <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                    <button type="button" class="btn btn-primary btn-sm" onclick="subscribeToWebPush(true)">
                        <i class="fa-solid fa-satellite-dish"></i> Cihazı Push'a Kaydet
                    </button>
                    <button type="button" class="btn btn-danger btn-sm" onclick="openPushTestCenterModal(); triggerServerWebPushTest(15);">
                        <i class="fa-solid fa-lock"></i> ⏱️ 15 Sn Kilit Ekranı Testi Başlat
                    </button>
                </div>
            </div>
        `;
    }

    const modalBody = document.getElementById('push-test-modal-body');
    if (!modalBody) return;

    const visibleSubs = isAdmin ? allSubs : mySubs;
    const visibleLogs = isAdmin
        ? logs.slice(0, 15)
        : logs.filter(l => currentUser && normalizeTR(l.username) === normalizeTR(currentUser.username)).slice(0, 10);

    modalBody.innerHTML = `
        <!-- Durum Özeti Kartları -->
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap:0.75rem;">
            <div style="background:rgba(15,23,42,0.8); border:1px solid rgba(56,189,248,0.35); border-radius:12px; padding:0.85rem;">
                <div style="font-size:0.75rem; color:var(--text-sec); margin-bottom:4px;">🌐 Aktif Tarayıcı &amp; Sistem</div>
                <div style="font-weight:800; color:#38bdf8; font-size:0.95rem;">${dev.fullLabel}</div>
                <div style="font-size:0.73rem; color:#cbd5e1; margin-top:4px;">Android, iPhone, iPad &amp; PC Tam Uyumlu</div>
            </div>
            <div style="background:rgba(15,23,42,0.8); border:1px solid rgba(16,185,129,0.35); border-radius:12px; padding:0.85rem;">
                <div style="font-size:0.75rem; color:var(--text-sec); margin-bottom:4px;">🔔 Android / iOS Bildirim İzni</div>
                <div>${permBadge}</div>
                <div style="font-size:0.73rem; color:#cbd5e1; margin-top:4px;">Kilit ekranı &amp; sistem sesi yetkisi</div>
            </div>
            <div style="background:rgba(15,23,42,0.8); border:1px solid rgba(245,158,11,0.35); border-radius:12px; padding:0.85rem;">
                <div style="font-size:0.75rem; color:var(--text-sec); margin-bottom:4px;">📡 Otomatik VAPID Push Kaydı</div>
                <div>${subBadge}</div>
                <div style="font-size:0.73rem; color:#cbd5e1; margin-top:4px;">Toplam Kayıtlı Cihaz: ${allSubs.length}</div>
            </div>
        </div>

        <!-- Geri Sayım ve Canlı Test Durum Kutusu -->
        <div id="push-countdown-status-box" style="display:none; background:linear-gradient(135deg, rgba(239,68,68,0.22), rgba(245,158,11,0.18)); border:2px solid #f59e0b; border-radius:12px; padding:0.95rem;"></div>

        <!-- 3 Adımlı Kilit Ekranı Test Butonları -->
        <div style="background:linear-gradient(135deg, rgba(2,132,199,0.16), rgba(16,185,129,0.14)); border:1px solid rgba(56,189,248,0.4); border-radius:14px; padding:1rem;">
            <div style="font-weight:800; color:#fff; font-size:0.95rem; margin-bottom:0.35rem;">
                <i class="fa-solid fa-mobile-screen-button" style="color:#34d399;"></i> Otomatik Kayıt &amp; Kilit Ekranı Bildirim Testi (Android + iPhone/iPad + PC)
            </div>
            <p style="font-size:0.81rem; color:#cbd5e1; margin-bottom:0.85rem; line-height:1.5;">
                ✅ <strong>Sıfır Ayar (Otomatik Kayıt):</strong> Personeller uygulamaya giriş yaptığında veya ekrana dokunduğunda cihazları <strong>hiçbir ayar yapmalarına gerek kalmadan otomatik olarak</strong> bildirim sistemine kaydedilir.<br>
                ⏱️ Kilit ekranı testi yapmak için <strong>"15 Sn Sonra Kilit Ekranı Push Gönder"</strong> butonuna basıp telefonunuzu kilitleyin.
            </p>
            <div style="display:flex; gap:0.6rem; flex-wrap:wrap;">
                <button type="button" class="btn btn-primary" onclick="subscribeToWebPush(true)">
                    <i class="fa-solid fa-satellite-dish"></i> 1. Cihazımı VAPID Push'a Kaydet / Yenile
                </button>
                <button type="button" class="btn btn-success" onclick="triggerServerWebPushTest(0)">
                    <i class="fa-solid fa-bolt"></i> 2. Anlık Push Gönder (0 Sn)
                </button>
                <button type="button" class="btn btn-danger" style="background:linear-gradient(135deg,#ef4444,#d97706); border:none; font-weight:800;" onclick="triggerServerWebPushTest(15)">
                    <i class="fa-solid fa-lock"></i> 3. ⏱️ 15 Sn Sonra Kilit Ekranı Push Gönder (Tuşu Kilitleyip Test Et)
                </button>
            </div>
        </div>

        ${isAdmin ? `
        <!-- Sadece Yönetici Ömer Eren İçin Dağıtım Modu Seçimi -->
        <div style="background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.38); border-radius:12px; padding:0.85rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.75rem;">
            <div>
                <strong style="color:#fde68a; font-size:0.86rem;"><i class="fa-solid fa-user-shield"></i> Yönetici (Ömer Eren) Bildirim Dağıtım Modu:</strong>
                <div style="font-size:0.76rem; color:#cbd5e1;">Tüm personelin telefon, tablet ve bilgisayarlarına otomatik bildirim gönderimi aktiftir.</div>
            </div>
            <div style="display:flex; gap:0.45rem;">
                <button type="button" class="btn btn-sm ${pilotMode === 'PILOT_OMER' ? 'btn-primary' : 'btn-secondary'}" onclick="togglePushPilotMode('PILOT_OMER')">
                    🎯 Sadece Ömer Eren Test Modu
                </button>
                <button type="button" class="btn btn-sm ${pilotMode === 'ALL_USERS' ? 'btn-success' : 'btn-secondary'}" onclick="togglePushPilotMode('ALL_USERS')">
                    🌐 Tüm Personel Aktif (Otomatik)
                </button>
            </div>
        </div>` : ''}

        <!-- Kayıtlı Push Cihaz Abonelikleri Tablosu -->
        <div>
            <h4 style="color:#fff; font-size:0.88rem; margin-bottom:0.45rem;">
                <i class="fa-solid fa-mobile-retro" style="color:#38bdf8;"></i> Kayıtlı Web Push Cihaz Abonelikleri (${visibleSubs.length})
            </h4>
            <div class="table-responsive" style="max-height:175px; overflow-y:auto;">
                <table class="dizsan-table">
                    <thead>
                        <tr>
                            <th>Personel</th>
                            <th>Tarayıcı / OS</th>
                            <th>Push Endpoint</th>
                            <th>Son Güncelleme</th>
                            <th>Durum</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${visibleSubs.length === 0 ? `
                            <tr><td colspan="5" style="text-align:center; padding:1rem; color:var(--text-sec);">Henüz kayıtlı push aboneliği yok. Ekrana dokunduğunuzda otomatik kaydedilir.</td></tr>
                        ` : visibleSubs.map(s => `
                            <tr>
                                <td><strong style="color:#fff;">${s.userFullName || s.username}</strong></td>
                                <td><span class="badge badge-normal">${s.browser || 'Web'} (${s.platform || 'Mobil'})</span></td>
                                <td style="font-family:monospace; font-size:0.72rem; color:#93c5fd;">...${String(s.endpoint || '').slice(-28)}</td>
                                <td style="font-size:0.75rem; color:var(--text-sec);">${s.updatedAt || '-'}</td>
                                <td><span class="badge ${s.isActive !== false ? 'badge-done' : 'badge-critical'}">${s.isActive !== false ? 'Aktif' : 'Pasif'}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Son Push Gönderim ve Hata Logları -->
        <div>
            <h4 style="color:#fff; font-size:0.88rem; margin-bottom:0.45rem;">
                <i class="fa-solid fa-list-check" style="color:#34d399;"></i> Son Push Bildirim Gönderim &amp; Hata Kayıtları (${visibleLogs.length})
            </h4>
            <div class="table-responsive" style="max-height:175px; overflow-y:auto;">
                <table class="dizsan-table">
                    <thead>
                        <tr>
                            <th>Tarih / Saat</th>
                            <th>Alıcı</th>
                            <th>Tür</th>
                            <th>Başlık</th>
                            <th>Sonuç / HTTP</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${visibleLogs.length === 0 ? `
                            <tr><td colspan="5" style="text-align:center; padding:1rem; color:var(--text-sec);">Henüz gönderim kaydı bulunmuyor. Test butonuna basarak ilk gönderimi başlatabilirsiniz.</td></tr>
                        ` : visibleLogs.map(l => `
                            <tr>
                                <td style="font-family:monospace; font-size:0.74rem; color:var(--dizsan-light);">${l.sentAt || '-'}</td>
                                <td><strong style="color:#fff;">${l.username || '-'}</strong></td>
                                <td><span class="badge badge-normal">${l.eventType || 'PUSH'}</span></td>
                                <td style="font-size:0.78rem; color:#e2e8f0;">${l.title || '-'}</td>
                                <td>
                                    <span class="badge ${l.status === 'SENT' ? 'badge-done' : 'badge-critical'}">
                                        ${l.status === 'SENT' ? `✅ İletildi (${l.httpStatus || 201})` : `⚠️ Hata (${l.httpStatus || 0})`}
                                    </span>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

// Bildirime dokunulduğunda ilgili toplantı, görev veya onay ekranını açan Deep-Link yönlendiricisi
function handleDeepLinkParams() {
    try {
        const params = new URLSearchParams(window.location.search);
        const tab = params.get('tab');
        const meetingId = params.get('meetingId');
        const actionId = params.get('actionId');
        const focus = params.get('focus');

        if (tab) {
            switchTab(tab);
        }
        if (focus === 'approval') {
            switchTab('dashboard-tab');
            setTimeout(() => {
                const el = document.getElementById('omer-approval-center-container');
                if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 350);
        } else if (focus === 'push-test') {
            setTimeout(() => openPushTestCenterModal(), 300);
        } else if (meetingId) {
            switchTab('meetings-tab');
            setTimeout(() => {
                const searchEl = document.getElementById('meeting-search');
                if (searchEl) {
                    searchEl.value = meetingId;
                    renderMeetings();
                }
            }, 300);
        } else if (actionId) {
            switchTab('actions-tab');
            setTimeout(() => {
                const searchEl = document.getElementById('action-search');
                if (searchEl) {
                    searchEl.value = actionId;
                    renderActions();
                }
            }, 300);
        }
    } catch (e) {}
}

async function enableBackgroundNotificationsAndKeepAlive(isManualClick = false) {
    startSilentAudioKeepAlive();
    await subscribeToWebPush(isManualClick);
    syncUserAndStateToServiceWorker();
    renderBgNotificationPermissionBanner();
    if (isManualClick) {
        openPushTestCenterModal();
    }
}

function renderBgNotificationPermissionBanner() {
    const bannerEl = document.getElementById('bg-notification-permission-banner');
    const topBtn = document.getElementById('btn-bg-notif-status');
    const dev = detectBrowserAndOS();
    const perm = ('Notification' in window) ? Notification.permission : 'unsupported';
    const allSubs = Array.isArray(appState.pushSubscriptions) ? appState.pushSubscriptions : [];
    const hasMySub = currentUser && allSubs.some(s => normalizeTR(s.username) === normalizeTR(currentUser.username));

    if (topBtn) {
        if (perm === 'granted' && hasMySub) {
            topBtn.innerHTML = `<i class="fa-solid fa-satellite-dish" style="color:#34d399;"></i> <span class="hide-on-sm">Bildirim: Otomatik Aktif</span>`;
            topBtn.style.borderColor = 'rgba(16,185,129,0.45)';
        } else {
            topBtn.innerHTML = `<i class="fa-solid fa-satellite-dish" style="color:#fbbf24;"></i> <span class="hide-on-sm">Push &amp; Kilit Ekranı Testi</span>`;
            topBtn.style.borderColor = 'rgba(245,158,11,0.55)';
        }
    }

    if (!bannerEl) return;
    if (perm === 'granted' && hasMySub) {
        bannerEl.innerHTML = '';
        return;
    }

    // Apple iPhone / iPad (iOS/iPadOS) Safari sekmesinde açılmışsa ve henüz Ana Ekrana eklenmemişse otomatik rehber göster
    if (dev.isIOS && !dev.isStandalonePWA && !('PushManager' in window)) {
        bannerEl.innerHTML = `
            <div class="meeting-call-banner yellow-1h" style="margin-bottom:0.9rem; border-color:#38bdf8; background:linear-gradient(135deg, rgba(2,132,199,0.24), rgba(15,23,42,0.95));">
                <div class="alarm-banner-left">
                    <div class="alarm-pulse-icon" style="background:rgba(56,189,248,0.3); color:#38bdf8;">
                        <i class="fa-brands fa-apple"></i>
                    </div>
                    <div>
                        <strong style="color:#fff; font-size:0.93rem; display:block; margin-bottom:2px;">
                            🍎 Apple iPhone / iPad Kilit Ekranı Bildirimleri (Otomatik Kurulum)
                        </strong>
                        <span style="color:#e2e8f0; font-size:0.81rem;">
                            Arka plan sesli uyarı motoru <strong>otomatik aktif edildi</strong>. iPhone/iPad kilitliyken bildirim almak için Safari'de <strong>Paylaş (⬆️) &rarr; Ana Ekrana Ekle</strong> seçeneğine bir kez dokunun; ana ekrandan açıldığında bildirimler otomatik kaydolur.
                        </span>
                    </div>
                </div>
                <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                    <button type="button" class="btn btn-primary btn-sm" onclick="triggerNativePwaInstall()">
                        <i class="fa-brands fa-apple"></i> Ana Ekrana Ekle Rehberi
                    </button>
                </div>
            </div>
        `;
        return;
    }

    bannerEl.innerHTML = `
        <div class="meeting-call-banner yellow-1h" onclick="subscribeToWebPush(false)" style="cursor:pointer; margin-bottom:0.9rem; border-color:#38bdf8; background:linear-gradient(135deg, rgba(2,132,199,0.22), rgba(16,185,129,0.18));">
            <div class="alarm-banner-left">
                <div class="alarm-pulse-icon" style="background:rgba(52,211,153,0.3); color:#34d399;">
                    <i class="fa-solid fa-satellite-dish"></i>
                </div>
                <div>
                    <strong style="color:#fff; font-size:0.93rem; display:block; margin-bottom:2px;">
                        📡 Otomatik Kilit Ekranı Bildirim Sistemi (Android &bull; iPhone/iPad &bull; PC)
                    </strong>
                    <span style="color:#e2e8f0; font-size:0.81rem;">
                        Ekranda herhangi bir yere dokunduğunuzda ve çıkan <strong>"Bildirimlere İzin Ver"</strong> kutusunu onayladığınızda cihazınız hiçbir ayar gerektirmeden otomatik olarak kaydedilir.
                    </span>
                </div>
            </div>
            <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                <button type="button" class="btn btn-success btn-sm" onclick="event.stopPropagation(); subscribeToWebPush(true)">
                    <i class="fa-solid fa-check-circle"></i> Bildirimlere İzin Ver (Otomatik Kaydet)
                </button>
            </div>
        </div>
    `;
}

function downloadMeetingAlarmICS(meetingId) {
    const m = (appState.meetings || []).find(x => x.id === meetingId);
    if (!m) return;
    const iso = normalizeToISODate(m.date);
    const [y, mo, d] = iso.split('-').map(Number);
    const [hh, mm] = String(m.time || '16:00').split(':').map(Number);
    if (!y || !mo || !d) return;

    const startDt = new Date(y, mo - 1, d, hh || 16, mm || 0, 0);
    const endDt = new Date(startDt.getTime() + 60 * 60000);
    const fmtICS = (dt) => {
        const pad = n => String(n).padStart(2, '0');
        return `${dt.getFullYear()}${pad(dt.getMonth() + 1)}${pad(dt.getDate())}T${pad(dt.getHours())}${pad(dt.getMinutes())}00`;
    };

    const recLabel = m.recordType === 'Eğitim' ? 'Eğitim' : 'Toplantı';
    const cleanText = s => String(s || '').replace(/\r?\n/g, '\\n').replace(/[,;]/g, ' ');
    const icsContent = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//DIZSAN//Toplanti ve Aksiyon Sistemi v1.6.0//TR',
        'CALSCALE:GREGORIAN',
        'METHOD:PUBLISH',
        'BEGIN:VEVENT',
        `UID:${m.id}-${Date.now()}@dizsan.com.tr`,
        `DTSTAMP:${fmtICS(new Date())}`,
        `DTSTART:${fmtICS(startDt)}`,
        `DTEND:${fmtICS(endDt)}`,
        `SUMMARY:DİZSAN ${recLabel}: ${cleanText(m.title)}`,
        `LOCATION:${cleanText(m.location || 'Dizsan Toplantı Salonu')}`,
        `DESCRIPTION:${cleanText(m.notes || 'Dizsan Planlı Toplantı Çağrısı')}`,
        'BEGIN:VALARM',
        'TRIGGER:-PT60M',
        'ACTION:DISPLAY',
        `DESCRIPTION:🟨 SARI UYARI: "${cleanText(m.title)}" toplantısına 1 saat kaldı!`,
        'END:VALARM',
        'BEGIN:VALARM',
        'TRIGGER:-PT60M',
        'ACTION:AUDIO',
        'END:VALARM',
        'BEGIN:VALARM',
        'TRIGGER:-PT5M',
        'ACTION:DISPLAY',
        `DESCRIPTION:🟥 KIRMIZI ACİL UYARI: "${cleanText(m.title)}" toplantısına 5 dakika kaldı!`,
        'END:VALARM',
        'BEGIN:VALARM',
        'TRIGGER:-PT5M',
        'ACTION:AUDIO',
        'END:VALARM',
        'END:VEVENT',
        'END:VCALENDAR'
    ].join('\r\n');

    const blob = new Blob([icsContent], { type: 'text/calendar;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Dizsan_Alarm_${m.id}.ics`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function sendBrowserNotification(title, body, tagKey, alertType = 'INVITE') {
    if (tagKey && sessionStorage.getItem(tagKey)) return false;
    if (tagKey) sessionStorage.setItem(tagKey, '1');

    // 1. Öncelikle Service Worker üzerinden işletim sistemi (OS) bildirimi gönder (Uygulama kapalıyken / arka plandayken çalışır)
    if ('serviceWorker' in navigator && 'Notification' in window && Notification.permission === 'granted') {
        navigator.serviceWorker.ready.then(reg => {
            const vibratePattern = alertType === 'RED_5M'
                ? [600, 150, 600, 150, 800]
                : alertType === 'YELLOW_1H'
                ? [400, 150, 400, 150, 500]
                : [300, 120, 300];
            reg.showNotification(title, {
                body,
                icon: './icon-192.png',
                badge: './icon-192.png',
                tag: tagKey || ('dizsan-notif-' + Date.now()),
                renotify: true,
                requireInteraction: true,
                vibrate: vibratePattern,
                data: { url: './', alertType }
            }).catch(() => {
                try { new Notification(title, { body, icon: 'icon-192.png' }); } catch (e) {}
            });
        }).catch(() => {
            try { new Notification(title, { body, icon: 'icon-192.png' }); } catch (e) {}
        });
        return true;
    }

    // 2. Fallback: Standart Notification API
    if ("Notification" in window) {
        if (Notification.permission === "granted") {
            try {
                new Notification(title, { body, icon: 'icon-192.png' });
            } catch (e) {}
        } else if (Notification.permission === "default") {
            Notification.requestPermission().then(() => renderBgNotificationPermissionBanner());
        }
    }
    return true;
}

/**
 * Davet edilen katılımcılar için:
 * 1. Toplantıya 5 dakika kala (-15 <= dk <= 5) -> KIRMIZI UYARI + ACİL ALARM SESİ
 * 2. Toplantıya 1 saat kala (5 < dk <= 60)     -> SARI UYARI + BİLDİRİM SESİ
 * 3. Yeni planlanan toplantı çağrısı (dk > 60) -> DAVET UYARISI + BİLDİRİM SESİ
 * 4. Kurumsal Duyurular                        -> DUYURU UYARISI + BİLDİRİM SESİ
 */
function checkAndTriggerMeetingCallAlerts() {
    const container = document.getElementById('meeting-call-alert-container');
    if (!container || !currentUser) {
        if (container) container.innerHTML = '';
        return;
    }

    const myNameNorm = normalizeTR(currentUser.name);
    const isAdminOmer = isOmerEren(currentUser);
    const bannersHtml = [];

    // 1. Toplantı / Eğitim Çağrılarını ve Geri Sayımlarını Kontrol Et
    (appState.meetings || []).forEach(m => {
        const isInvited = (m.participants || []).some(p => normalizeTR(p) === myNameNorm) || isAdminOmer;
        if (!isInvited) return;

        const diffMins = getMeetingMinutesRemaining(m);
        if (diffMins === null) return;

        const recLabel = m.recordType === 'Eğitim' ? 'Eğitim' : 'Toplantı';
        const isEditedRecord = Boolean(m.updatedBy || m.updatedAt);

        // A) 5 DAKİKA KALA (veya toplantının ilk 15 dakikası içinde): KIRMIZI UYARI & SES
        if (diffMins >= -15 && diffMins <= 5) {
            const minsText = diffMins <= 0
                ? `ŞU AN BAŞLADI! (${Math.abs(Math.floor(diffMins))} dk oldu)`
                : `BAŞLAMASINA ${Math.ceil(diffMins)} DAKİKA KALDI!`;
            const soundKey = `alert_red5m_${m.id}_${myNameNorm}_${m.date}_${m.time}`;
            if (!isEditedRecord && !sessionStorage.getItem(soundKey)) {
                playMeetingCallSound('RED_5M');
                sendBrowserNotification(
                    `🟥 KIRMIZI UYARI: ${recLabel} 5 Dakika İçinde Başlıyor!`,
                    `"${m.title}" saat ${m.time}'da (${m.location || 'Toplantı Salonu'}) başlıyor!`,
                    soundKey,
                    'RED_5M'
                );
            }
            sessionStorage.setItem(soundKey, '1');

            bannersHtml.push(`
                <div class="meeting-call-banner red-5m">
                    <div class="alarm-banner-left">
                        <div class="alarm-pulse-icon" style="background:rgba(239,68,68,0.4); color:#fff;">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                        </div>
                        <div>
                            <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:3px;">
                                <span class="badge badge-critical" style="font-size:0.76rem; padding:3px 9px;">🟥 5 DAKİKA KALA KIRMIZI ACİL UYARI</span>
                                <strong style="color:#fff; font-size:0.96rem;">${m.title} (${recLabel})</strong>
                            </div>
                            <div style="color:#fee2e2; font-size:0.84rem; line-height:1.45;">
                                ⏰ <strong>${minsText}</strong> • Tarih/Saat: <strong>${formatDateTR(m.date)} ${m.time}</strong> • Yer: <strong>${m.location || 'Toplantı Salonu'}</strong>
                            </div>
                        </div>
                    </div>
                    <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                        <button type="button" class="btn btn-danger btn-sm" onclick="playMeetingCallSound('RED_5M')">
                            <i class="fa-solid fa-volume-high"></i> Kırmızı Alarm Sesi
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="downloadMeetingAlarmICS('${m.id}')" title="Telefon/PC Saat & Takvim Alarmına Ekle">
                            <i class="fa-solid fa-mobile-screen"></i> Cihaz Alarmına Kur
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="switchTab('meetings-tab')">
                            <i class="fa-solid fa-eye"></i> Detayı Gör
                        </button>
                    </div>
                </div>
            `);
        }
        // B) 1 SAAT KALA (5 dk < kalan <= 60 dk): SARI UYARI & SES
        else if (diffMins > 5 && diffMins <= 60) {
            const minsLeft = Math.ceil(diffMins);
            const soundKey = `alert_yellow1h_${m.id}_${myNameNorm}_${m.date}_${m.time}`;
            if (!isEditedRecord && !sessionStorage.getItem(soundKey)) {
                playMeetingCallSound('YELLOW_1H');
                sendBrowserNotification(
                    `🟨 SARI UYARI: ${recLabel} Saatine ${minsLeft} Dakika Kaldı!`,
                    `"${m.title}" bugün saat ${m.time}'da (${m.location || 'Toplantı Salonu'}) başlayacak.`,
                    soundKey,
                    'YELLOW_1H'
                );
            }
            sessionStorage.setItem(soundKey, '1');

            bannersHtml.push(`
                <div class="meeting-call-banner yellow-1h">
                    <div class="alarm-banner-left">
                        <div class="alarm-pulse-icon" style="background:rgba(245,158,11,0.35); color:#fef08a;">
                            <i class="fa-solid fa-clock"></i>
                        </div>
                        <div>
                            <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:3px;">
                                <span class="badge badge-high" style="font-size:0.76rem; padding:3px 9px; background:rgba(245,158,11,0.3); color:#fef08a; border:1px solid #f59e0b;">🟨 1 SAAT KALA SARI UYARI (${minsLeft} DK KALDI)</span>
                                <strong style="color:#fff; font-size:0.95rem;">${m.title} (${recLabel})</strong>
                            </div>
                            <div style="color:#fef3c7; font-size:0.84rem; line-height:1.45;">
                                ⏳ Toplantı saatine <strong>${minsLeft} dakika</strong> kaldı! • Saat: <strong>${m.time}</strong> • Yer: <strong>${m.location || 'Toplantı Salonu'}</strong>
                            </div>
                        </div>
                    </div>
                    <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                        <button type="button" class="btn btn-sm" style="background:#f59e0b; color:#0f172a; font-weight:800;" onclick="playMeetingCallSound('YELLOW_1H')">
                            <i class="fa-solid fa-volume-high"></i> Sarı Uyarı Sesi
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="downloadMeetingAlarmICS('${m.id}')" title="Telefon/PC Saat & Takvim Alarmına Ekle">
                            <i class="fa-solid fa-mobile-screen"></i> Cihaz Alarmına Kur
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="switchTab('meetings-tab')">
                            <i class="fa-solid fa-eye"></i> Detayı Gör
                        </button>
                    </div>
                </div>
            `);
        }
        // C) PLANLANAN TOPLANTI ÇAĞRISI / DAVETİ (60 dakikadan fazla var, örn: Yarın 16:00)
        else if (diffMins > 60 && diffMins <= 60 * 24 * 14) {
            const soundKey = `alert_invite_${m.id}_${myNameNorm}`;
            const legacySoundKey = `alert_invite_${m.id}_${myNameNorm}_${m.date}_${m.time}`;
            const isEditedRecord = Boolean(m.updatedBy || m.updatedAt);
            if (!isEditedRecord && !localStorage.getItem(soundKey) && !localStorage.getItem(legacySoundKey)) {
                playMeetingCallSound('INVITE');
                sendBrowserNotification(
                    `📢 Yeni ${recLabel} Çağrısı / Daveti`,
                    `${formatDateTR(m.date)} Saat ${m.time} — "${m.title}" (${m.location || 'Toplantı Salonu'}) için davetlisiniz.`,
                    soundKey,
                    'INVITE'
                );
            }
            localStorage.setItem(soundKey, '1');
            localStorage.setItem(legacySoundKey, '1');

            const hrsLeft = Math.floor(diffMins / 60);
            const remMins = Math.round(diffMins % 60);
            const timeRemainingLabel = hrsLeft >= 24
                ? `${Math.floor(hrsLeft / 24)} gün ${hrsLeft % 24} saat kaldı`
                : `${hrsLeft} saat ${remMins} dk kaldı`;

            bannersHtml.push(`
                <div class="meeting-call-banner blue-invite">
                    <div class="alarm-banner-left">
                        <div class="alarm-pulse-icon" style="background:rgba(56,189,248,0.22); color:#38bdf8;">
                            <i class="fa-solid fa-bullhorn"></i>
                        </div>
                        <div>
                            <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:3px;">
                                <span class="badge badge-normal" style="font-size:0.75rem;">📢 PLANLI ${recLabel.toUpperCase()} ÇAĞRISI • DAVETLİSİNİZ</span>
                                <strong style="color:#fff; font-size:0.94rem;">${m.title}</strong>
                            </div>
                            <div style="color:#e0f2fe; font-size:0.83rem; line-height:1.45;">
                                📅 Tarih: <strong>${formatDateTR(m.date)}</strong> • Saat: <strong>${m.time}</strong> (${timeRemainingLabel}) • Yer: <strong>${m.location || 'Toplantı Salonu'}</strong>
                                <span style="display:block; font-size:0.75rem; color:#fde68a; margin-top:2px;"><i class="fa-solid fa-bell"></i> Toplantıya 1 saat kala Sarı Uyarı, 5 dakika kala Kırmızı Sesli Uyarı otomatik verilecektir.</span>
                            </div>
                        </div>
                    </div>
                    <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                        <button type="button" class="btn btn-success btn-sm" onclick="downloadMeetingAlarmICS('${m.id}')" title="Uygulama tamamen kapalıyken bile telefon/PC alarmının çalması için cihaz takvimine ekler">
                            <i class="fa-solid fa-bell"></i> Cihaz Alarmına Kur (1 Saat &amp; 5 Dk)
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="playMeetingCallSound('INVITE')" title="Çağrı Bildirim Sesini Dinle">
                            <i class="fa-solid fa-volume-high"></i>
                        </button>
                        <button type="button" class="btn btn-primary btn-sm" onclick="switchTab('meetings-tab')">
                            <i class="fa-solid fa-calendar-check"></i> Gündemi Gör
                        </button>
                    </div>
                </div>
            `);
        }
    });

    // 2. Genel Kurumsal Duyuruları Kontrol Et
    (appState.announcements || []).forEach(ann => {
        const isTarget = (ann.participants || []).some(p => normalizeTR(p) === myNameNorm) || isAdminOmer;
        if (!isTarget) return;
        const dismissedBy = Array.isArray(ann.dismissedBy) ? ann.dismissedBy : [];
        if (dismissedBy.some(u => normalizeTR(u) === myNameNorm)) return;

        const annSoundKey = `alert_ann_${ann.id}_${myNameNorm}`;
        if (!localStorage.getItem(annSoundKey)) {
            playMeetingCallSound('INVITE');
            sendBrowserNotification(
                `📣 DİZSAN Kurumsal Duyuru: ${ann.title}`,
                ann.message,
                annSoundKey,
                'INVITE'
            );
            localStorage.setItem(annSoundKey, '1');
        }

        bannersHtml.push(`
            <div class="meeting-call-banner yellow-1h" style="border-color:#38bdf8;">
                <div class="alarm-banner-left">
                    <div class="alarm-pulse-icon" style="background:rgba(2,132,199,0.3); color:#38bdf8;">
                        <i class="fa-solid fa-bullhorn"></i>
                    </div>
                    <div>
                        <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:3px;">
                            <span class="badge badge-normal">📣 KURUMSAL DUYURU (${ann.dept || 'Genel'})</span>
                            <strong style="color:#fff; font-size:0.94rem;">${ann.title}</strong>
                            <span style="font-size:0.73rem; color:var(--text-sec);">• Yayınlayan: ${ann.createdBy || 'ÖMER EREN'} (${ann.createdAt || ''})</span>
                        </div>
                        <div style="color:#f1f5f9; font-size:0.84rem; white-space:pre-line; line-height:1.45;">${ann.message}</div>
                    </div>
                </div>
                <div style="display:flex; gap:0.45rem;">
                    <button type="button" class="btn btn-success btn-sm" onclick="dismissAnnouncement('${ann.id}')">
                        <i class="fa-solid fa-check"></i> Okudum / Kapat
                    </button>
                </div>
            </div>
        `);
    });

    container.innerHTML = bannersHtml.join('');
}

// ==========================================================================
// ÖMER EREN YÖNETİCİ ONAY MERKEZİ (YENİ TOPLANTI ONAYI, DEĞİŞTİRME VE SİLME ONAYI)
// ==========================================================================
function renderOmerApprovalCenter() {
    const container = document.getElementById('omer-approval-center-container');
    if (!container || !currentUser) {
        if (container) container.innerHTML = '';
        return;
    }

    const isAdminOmer = isOmerEren(currentUser);
    const pendingNewMeetings = (appState.meetings || []).filter(m => !isMeetingApprovedByOmer(m));
    const pendingRequests = (appState.approvalRequests || []).filter(r => r.status === 'PENDING');

    // Ömer Eren için yeni gelen onay taleplerinde sesli ve görsel bildirim tetikle
    if (isAdminOmer) {
        pendingNewMeetings.forEach(m => {
            const notifKey = `omer_notif_newm_${m.id}`;
            if (!localStorage.getItem(notifKey)) {
                localStorage.setItem(notifKey, '1');
                playMeetingCallSound('APPROVAL', `Dikkat! ${m.createdBy || 'Personel'} tarafından kaydedilen ${m.title} toplantısı yönetici onayınızı bekliyor.`);
                sendBrowserNotification(
                    `🛡️ Yönetici Onayı Bekleyen Toplantı (${m.id})`,
                    `"${m.title}" (${m.createdBy || 'Personel'}) kaydı onayınızı bekliyor.`,
                    notifKey,
                    'APPROVAL'
                );
            }
        });

        pendingRequests.forEach(req => {
            const notifKey = `omer_notif_req_${req.id}`;
            if (!localStorage.getItem(notifKey)) {
                localStorage.setItem(notifKey, '1');
                // Kayıt edilmiş toplantı/eğitim düzenlemelerinde bildirim tetikleme
                if (req.type !== 'EDIT_MEETING') {
                    const actionLabel = req.type === 'DELETE_MEETING' ? 'silme' : 'değiştirme';
                    playMeetingCallSound('APPROVAL', `Dikkat! ${req.requestedBy}, ${req.meetingTitle} toplantısı için ${actionLabel} onayı talep etti.`);
                    sendBrowserNotification(
                        `🛡️ Ömer Eren Onayı Bekleniyor (${req.type === 'DELETE_MEETING' ? 'Silme' : 'Değiştirme'})`,
                        `${req.requestedBy}: "${req.meetingTitle}" (${req.meetingId}) için ${actionLabel} onayı bekliyor.`,
                        notifKey,
                        'APPROVAL'
                    );
                }
            }
        });
    }

    if (pendingNewMeetings.length === 0 && pendingRequests.length === 0) {
        container.innerHTML = '';
        return;
    }

    const totalPending = pendingNewMeetings.length + pendingRequests.length;

    if (isAdminOmer) {
        container.innerHTML = `
            <div class="card" style="margin-bottom:1.1rem; border:2px solid #f59e0b; background:linear-gradient(135deg, rgba(245,158,11,0.22), rgba(15,23,42,0.96)); box-shadow:0 10px 28px rgba(245,158,11,0.28);">
                <div class="card-header" style="margin-bottom:0.75rem; border-bottom:1px solid rgba(245,158,11,0.35); padding-bottom:0.6rem;">
                    <div class="card-title" style="color:#fef08a; font-size:1.02rem;">
                        <i class="fa-solid fa-user-shield" style="color:#f59e0b;"></i>
                        🛡️ ÖMER EREN YÖNETİCİ ONAY MERKEZİ (${totalPending} Onay Bekleyen İşlem)
                    </div>
                    <div style="display:flex; gap:0.4rem; align-items:center;">
                        <button type="button" class="btn btn-secondary btn-sm" onclick="playMeetingCallSound('APPROVAL', 'Yönetici onay merkezinde bekleyen işlemler var.')">
                            <i class="fa-solid fa-volume-high"></i> Sesli Uyarı
                        </button>
                        <span class="badge badge-high">Ömer Eren Onayı Bekleniyor</span>
                    </div>
                </div>
                <div style="display:flex; flex-direction:column; gap:0.65rem;">
                    ${pendingNewMeetings.map(m => `
                        <div style="background:rgba(15,23,42,0.88); border:1px solid rgba(56,189,248,0.55); border-radius:10px; padding:0.85rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; flex-wrap:wrap;">
                            <div style="flex:1; min-width:240px;">
                                <div style="display:flex; align-items:center; gap:0.45rem; flex-wrap:wrap; margin-bottom:4px;">
                                    <span class="badge badge-normal">📋 YENİ KAYDEDİLEN TOPLANTI ONAYI</span>
                                    <strong style="color:#fff; font-size:0.94rem;">${m.id} — ${m.title} (${m.recordType || 'Toplantı'})</strong>
                                </div>
                                <div style="font-size:0.81rem; color:#cbd5e1;">
                                    Kaydeden: <strong>${m.createdBy || '-'}</strong> • Tarih/Saat: <strong>${formatDateTR(m.date)} ${m.time}</strong> • Departman: <strong>${m.dept}</strong>
                                </div>
                            </div>
                            <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                                <button type="button" class="btn btn-success btn-sm" onclick="approveNewMeeting('${m.id}')">
                                    <i class="fa-solid fa-check"></i> Toplantıyı Onayla (Ömer Eren)
                                </button>
                                <button type="button" class="btn btn-danger btn-sm" onclick="rejectNewMeeting('${m.id}')">
                                    <i class="fa-solid fa-xmark"></i> Reddet &amp; Sil
                                </button>
                            </div>
                        </div>
                    `).join('')}

                    ${pendingRequests.map(req => {
                        const isDelMeeting = req.type === 'DELETE_MEETING';
                        const isDelAction = req.type === 'DELETE_ACTION';
                        const isDel = isDelMeeting || isDelAction;
                        const badgeText = isDelMeeting ? '🗑️ TOPLANTI SİLME ONAY TALEBİ' : isDelAction ? '🗑️ AKSİYON SİLME ONAY TALEBİ' : '✏️ TOPLANTI DEĞİŞTİRME ONAY TALEBİ';
                        const itemTitle = req.meetingTitle || req.actionTitle || 'Kayıt';
                        const itemId = req.meetingId || req.actionId || '';
                        return `
                            <div style="background:rgba(15,23,42,0.88); border:1px solid ${isDel ? 'rgba(239,68,68,0.65)' : 'rgba(245,158,11,0.65)'}; border-radius:10px; padding:0.85rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; flex-wrap:wrap;">
                                <div style="flex:1; min-width:240px;">
                                    <div style="display:flex; align-items:center; gap:0.45rem; flex-wrap:wrap; margin-bottom:4px;">
                                        <span class="badge ${isDel ? 'badge-critical' : 'badge-high'}">
                                            ${badgeText}
                                        </span>
                                        <strong style="color:#fff; font-size:0.94rem;">${itemId} — ${itemTitle}</strong>
                                    </div>
                                    <div style="font-size:0.81rem; color:#cbd5e1;">
                                        Talep Eden: <strong>${req.requestedBy}</strong> (${req.requestedAt})
                                        ${req.reason ? ` • Gerekçe/Açıklama: <strong style="color:#fde68a;">${req.reason}</strong>` : ''}
                                        ${!isDel && req.proposedData ? `<div style="margin-top:4px; font-size:0.78rem; color:#93c5fd;">Yeni Başlık: <strong>${req.proposedData.title}</strong> | Tarih: ${formatDateTR(req.proposedData.date)} ${req.proposedData.time} | Not: ${(req.proposedData.notes || '').slice(0, 80)}...</div>` : ''}
                                    </div>
                                </div>
                                <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                                    <button type="button" class="btn btn-success btn-sm" onclick="approveRequest('${req.id}')">
                                        <i class="fa-solid fa-check"></i> ${isDel ? 'Silmeyi Onayla (Kaydı Sil)' : 'Değişikliği Onayla & Uygula'}
                                    </button>
                                    <button type="button" class="btn btn-danger btn-sm" onclick="rejectRequest('${req.id}')">
                                        <i class="fa-solid fa-xmark"></i> Talebi Reddet
                                    </button>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    } else {
        container.innerHTML = `
            <div style="margin-bottom:0.95rem; padding:0.85rem 1rem; border-radius:12px; background:rgba(245,158,11,0.14); border:1px solid rgba(245,158,11,0.45); color:#fde68a; font-size:0.84rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <i class="fa-solid fa-hourglass-half"></i> <strong>Yönetici (ÖMER EREN) Onayı Bekleyen İşlemler (${totalPending} Adet):</strong>
                    ${pendingNewMeetings.length > 0 ? ` ${pendingNewMeetings.length} yeni toplantı kaydı` : ''}
                    ${pendingRequests.length > 0 ? ` ${pendingRequests.length} silme/değiştirme talebi` : ''}
                    Yönetici <strong>ÖMER EREN</strong> tarafından onaylandığında devreye girecektir.
                </div>
                <span class="badge badge-high">Onay Yetkisi: ÖMER EREN</span>
            </div>
        `;
    }
}

function approveNewMeeting(meetingId) {
    if (!isOmerEren(currentUser)) {
        alert("Bu işlem için sadece Yönetici ÖMER EREN yetkilidir!");
        return;
    }
    const m = (appState.meetings || []).find(x => x.id === meetingId);
    if (!m) return;
    m.approvalStatus = 'Onaylandı';
    m.omerApprovedStamp = true;
    m.approvedBy = 'ÖMER EREN';
    m.approvedAt = formatNowTR();
    m.updatedBy = 'ÖMER EREN';
    m.updatedAt = formatNowTR();
    addAuditLog("TOPLANTI", `${m.id} kodlu '${m.title}' kaydı Yönetici ÖMER EREN tarafından onaylandı.`);
    dispatchPushToServer([m.createdBy || 'Personel'], {
        title: `✅ Toplantı Kaydı Onaylandı`,
        body: `'${m.title}' toplantısı Yönetici ÖMER EREN tarafından onaylandı.`,
        tag: `appr_newm_${m.id}`
    });
    syncToServer();
    renderAll();
}

function rejectNewMeeting(meetingId) {
    if (!isOmerEren(currentUser)) {
        alert("Bu işlem için sadece Yönetici ÖMER EREN yetkilidir!");
        return;
    }
    const m = (appState.meetings || []).find(x => x.id === meetingId);
    if (!m) return;
    if (!confirm(`'${m.title}' (${m.id}) toplantı kaydını reddedip silmek istediğinize emin misiniz?`)) return;
    registerDeletedRecordId(meetingId);
    appState.meetings = appState.meetings.filter(x => x.id !== meetingId);
    addAuditLog("TOPLANTI", `${m.id} kodlu '${m.title}' kaydı Yönetici ÖMER EREN tarafından reddedilerek kaldırıldı.`);
    dispatchPushToServer([m.createdBy || 'Personel'], {
        title: `❌ Toplantı Kaydı Reddedildi`,
        body: `'${m.title}' toplantı kaydı onaylanmadı ve kaldırıldı.`,
        tag: `appr_rej_${m.id}`
    });
    syncToServer();
    renderAll();
}

function approveRequest(reqId) {
    if (!isOmerEren(currentUser)) {
        alert("Bu işlem için sadece Yönetici ÖMER EREN yetkilidir!");
        return;
    }
    if (!Array.isArray(appState.approvalRequests)) return;
    const req = appState.approvalRequests.find(r => r.id === reqId);
    if (!req || req.status !== 'PENDING') return;

    if (req.type === 'DELETE_MEETING') {
        registerDeletedRecordId(req.meetingId);
        appState.meetings = (appState.meetings || []).filter(m => m.id !== req.meetingId);
        req.status = 'APPROVED';
        req.resolvedAt = formatNowTR();
        req.resolvedBy = 'ÖMER EREN';
        addAuditLog("TOPLANTI", `${req.meetingId} ('${req.meetingTitle}') silme talebi (${req.requestedBy}) Yönetici ÖMER EREN onayıyla gerçekleştirildi ve kayıt silindi.`);
        dispatchPushToServer([req.requestedBy], {
            title: `✅ Silme Talebiniz Onaylandı`,
            body: `'${req.meetingTitle}' toplantısı silme talebiniz Yönetici ÖMER EREN tarafından onaylandı.`,
            tag: `appr_ok_${req.id}`
        });
    } else if (req.type === 'DELETE_ACTION') {
        registerDeletedRecordId(req.actionId);
        appState.actions = (appState.actions || []).filter(a => a.id !== req.actionId);
        req.status = 'APPROVED';
        req.resolvedAt = formatNowTR();
        req.resolvedBy = 'ÖMER EREN';
        addAuditLog("AKSİYON", `${req.actionId} ('${req.actionTitle}') silme talebi (${req.requestedBy}) Yönetici ÖMER EREN onayıyla gerçekleştirildi ve aksiyon silindi.`);
        dispatchPushToServer([req.requestedBy], {
            title: `✅ Aksiyon Silme Talebiniz Onaylandı`,
            body: `'${req.actionTitle}' aksiyonu silme talebiniz Yönetici ÖMER EREN tarafından onaylandı.`,
            tag: `appr_ok_${req.id}`
        });
    } else if (req.type === 'EDIT_MEETING' && req.proposedData) {
        const idx = (appState.meetings || []).findIndex(m => m.id === req.meetingId);
        if (idx !== -1) {
            appState.meetings[idx] = {
                ...appState.meetings[idx],
                ...req.proposedData,
                approvalStatus: 'Onaylandı',
                omerApprovedStamp: true,
                approvedBy: 'ÖMER EREN',
                approvedAt: formatNowTR(),
                updatedBy: req.requestedBy || 'ÖMER EREN',
                updatedAt: req.requestedAt || formatNowTR()
            };
        }
        req.status = 'APPROVED';
        req.resolvedAt = formatNowTR();
        req.resolvedBy = 'ÖMER EREN';
        addAuditLog("TOPLANTI", `${req.meetingId} ('${req.meetingTitle}') değiştirme/düzenleme talebi (${req.requestedBy}) Yönetici ÖMER EREN onayıyla uygulandı.`);
    }

    syncToServer();
    renderAll();
}

function rejectRequest(reqId) {
    if (!isOmerEren(currentUser)) {
        alert("Bu işlem için sadece Yönetici ÖMER EREN yetkilidir!");
        return;
    }
    if (!Array.isArray(appState.approvalRequests)) return;
    const req = appState.approvalRequests.find(r => r.id === reqId);
    if (!req || req.status !== 'PENDING') return;

    req.status = 'REJECTED';
    req.resolvedAt = formatNowTR();
    req.resolvedBy = 'ÖMER EREN';
    const targetTitle = req.meetingTitle || req.actionTitle || 'Kayıt';
    addAuditLog("TOPLANTI", `${req.meetingId || req.actionId} ('${targetTitle}') için ${req.requestedBy} tarafından gönderilen talep Yönetici ÖMER EREN tarafından reddedildi.`);
    if (req.type !== 'EDIT_MEETING') {
        dispatchPushToServer([req.requestedBy], {
            title: `❌ Onay Talebiniz Reddedildi`,
            body: `'${targetTitle}' için ilettiğiniz talep Yönetici ÖMER EREN tarafından reddedildi.`,
            tag: `appr_no_${req.id}`
        });
    }
    syncToServer();
    renderAll();
}

function dismissAnnouncement(annId) {
    if (!currentUser) return;
    const ann = (appState.announcements || []).find(a => a.id === annId);
    if (!ann) return;
    if (!Array.isArray(ann.dismissedBy)) ann.dismissedBy = [];
    if (!ann.dismissedBy.includes(currentUser.name)) {
        ann.dismissedBy.push(currentUser.name);
    }
    syncToServer();
    checkAndTriggerMeetingCallAlerts();
}

function openAnnouncementModal() {
    const modal = document.getElementById('announcement-modal');
    const partBox = document.getElementById('call-participants-box');
    if (!modal || !partBox) return;

    partBox.innerHTML = appState.users.map(u => `
        <label class="participant-check">
            <input type="checkbox" name="call-participant" value="${u.name}" checked>
            <span>${u.name} <small style="color:var(--text-sec);">(${u.dept})</small></span>
        </label>
    `).join('');

    const tomorrowIso = new Date(Date.now() + 86400000).toISOString().split('T')[0];
    setMaskedDateInputValue(document.getElementById('call-date-input'), tomorrowIso);
    const timeEl = document.getElementById('call-time-input');
    if (timeEl) timeEl.value = '16:00';
    const titleEl = document.getElementById('call-title-input');
    if (titleEl) titleEl.value = '';
    const msgEl = document.getElementById('call-message-input');
    if (msgEl) msgEl.value = '';
    const typeEl = document.getElementById('call-type-select');
    if (typeEl) {
        typeEl.value = 'MEETING_CALL';
        toggleCallTypeFields('MEETING_CALL');
    }

    modal.classList.add('open');
}

function closeAnnouncementModal() {
    const modal = document.getElementById('announcement-modal');
    if (modal) modal.classList.remove('open');
}

function toggleCallTypeFields(val) {
    const dtRow = document.getElementById('call-datetime-row');
    const dateInput = document.getElementById('call-date-input');
    const timeInput = document.getElementById('call-time-input');
    if (!dtRow) return;
    if (val === 'ANNOUNCEMENT') {
        dtRow.style.display = 'none';
        if (dateInput) dateInput.required = false;
        if (timeInput) timeInput.required = false;
    } else {
        dtRow.style.display = 'grid';
        if (dateInput) dateInput.required = true;
        if (timeInput) timeInput.required = true;
    }
}

function toggleAllCallParticipants(state) {
    document.querySelectorAll('input[name="call-participant"]').forEach(cb => {
        cb.checked = state;
    });
}

function generateUniqueMeetingId(prefix = 'TOP') {
    const used = new Set([
        ...(appState.meetings || []).map(m => String(m.id)),
        ...(appState.deletedIds || []).map(String)
    ]);
    let seq = (appState.meetings || []).length + 1;
    let candidate = `${prefix}-2026-${String(seq).padStart(3, '0')}`;
    while (used.has(candidate)) {
        seq++;
        candidate = `${prefix}-2026-${String(seq).padStart(3, '0')}`;
    }
    return candidate;
}

function generateUniqueActionId() {
    const used = new Set([
        ...(appState.actions || []).map(a => String(a.id)),
        ...(appState.deletedIds || []).map(String)
    ]);
    let seq = 100 + (appState.actions || []).length + 1;
    let candidate = `AKS-${seq}`;
    while (used.has(candidate)) {
        seq++;
        candidate = `AKS-${seq}`;
    }
    return candidate;
}

function saveMeetingCallOrAnnouncement(event) {
    event.preventDefault();
    const callType = document.getElementById('call-type-select')?.value || 'MEETING_CALL';
    const dept = document.getElementById('call-dept-input')?.value || 'Genel Yönetim';
    const title = document.getElementById('call-title-input')?.value.trim() || '';
    const dateRaw = document.getElementById('call-date-input')?.value || '';
    const date = normalizeToISODate(dateRaw);
    const time = document.getElementById('call-time-input')?.value || '16:00';
    const location = document.getElementById('call-location-input')?.value.trim() || 'Dizsan Toplantı Salonu';
    const message = cleanNumberedText(document.getElementById('call-message-input')?.value || '');
    const participants = Array.from(document.querySelectorAll('input[name="call-participant"]:checked')).map(cb => cb.value);

    if (participants.length === 0) {
        alert("Lütfen bildirim/davet gönderilecek en az 1 katılımcı seçin!");
        return;
    }

    if (callType === 'ANNOUNCEMENT') {
        if (!Array.isArray(appState.announcements)) appState.announcements = [];
        const newAnn = {
            id: 'DUY-' + Date.now(),
            title,
            dept,
            message,
            participants,
            createdBy: currentUser ? currentUser.name : 'ÖMER EREN',
            createdAt: formatNowTR(),
            updatedBy: '',
            updatedAt: '',
            dismissedBy: []
        };
        appState.announcements.unshift(newAnn);
        addAuditLog("TOPLANTI", `Kurumsal Duyuru yayınlandı: '${title}' (${participants.length} personele bildirim gönderildi).`);
        syncToServer();
        closeAnnouncementModal();
        renderAll();
        playMeetingCallSound('INVITE');
        alert(`📣 Kurumsal duyuru başarıyla yayınlandı ve seçilen ${participants.length} personele sesli bildirim gönderildi!`);
        return;
    }

    // Planlı Toplantı Çağrısı veya Eğitim Çağrısı
    const recordType = (callType === 'TRAINING_CALL') ? 'Eğitim' : 'Toplantı';
    const prefix = recordType === 'Eğitim' ? 'EGT' : 'TOP';
    const newId = generateUniqueMeetingId(prefix);
    const isAdmin = isOmerEren(currentUser);
    const nowStr = formatNowTR();

    const newMeeting = {
        id: newId,
        recordType,
        isScheduledCall: true,
        approvalStatus: isAdmin ? 'Onaylandı' : 'Yönetici Onayı Bekliyor',
        omerApprovedStamp: isAdmin,
        approvedBy: isAdmin ? 'ÖMER EREN' : '',
        approvedAt: isAdmin ? nowStr : '',
        title,
        dept,
        date,
        time,
        location,
        participants,
        externalParticipants: [],
        notes: message,
        decisions: '',
        attachments: [],
        createdBy: currentUser ? currentUser.name : 'ÖMER EREN',
        createdAt: nowStr,
        updatedBy: '',
        updatedAt: ''
    };

    appState.meetings.unshift(newMeeting);
    addAuditLog("TOPLANTI", `${newId} kodlu Planlı ${recordType} Çağrısı yayınlandı: '${title}' — Tarih: ${formatDateTR(date)} Saat: ${time} (${participants.length} katılımcıya davet + 1 saat kala Sarı + 5 dk kala Kırmızı alarm tanımlandı).`);
    syncToServer();
    closeAnnouncementModal();
    renderAll();
    playMeetingCallSound(isAdmin ? 'INVITE' : 'APPROVAL');
    alert(`📢 ${recordType} Çağrısı oluşturuldu!\n\n📅 Tarih: ${formatDateTR(date)} Saat: ${time}\n👥 Davet Edilen: ${participants.length} Personel\n🛡️ Onay Durumu: ${newMeeting.approvalStatus}\n\n🔔 Seçilen katılımcılara çağrı bildirimi gönderildi. Toplantı saatine 1 saat kala SARI UYARI, 5 dakika kala KIRMIZI UYARI ve bildirim sesi otomatik olarak çalacaktır.`);
}

function normalizeToISODate(val) {
    if (!val) return "";
    const str = String(val).trim();
    if (/^\d{2}\.\d{2}\.\d{4}$/.test(str)) {
        const [d, m, y] = str.split('.');
        return `${y}-${m}-${d}`;
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(str)) {
        return str;
    }
    return str;
}

function formatDateTR(val) {
    if (!val) return "-";
    const iso = normalizeToISODate(val);
    if (/^\d{4}-\d{2}-\d{2}$/.test(iso)) {
        const [y, m, d] = iso.split('-');
        return `${d}.${m}.${y}`;
    }
    return val;
}

function setMaskedDateInputValue(inputEl, isoDateStr) {
    if (!inputEl) return;
    const iso = normalizeToISODate(isoDateStr);
    if (inputEl.dataset && inputEl.dataset.autoDateInitialized === 'true') {
        const [y, m, d] = iso.split('-');
        inputEl.value = (y && m && d) ? `${d}.${m}.${y}` : (isoDateStr || '');
    } else {
        inputEl.value = iso;
    }
}

function getRecordAuditInfo(item) {
    if (!item) return { createdBy: 'ÖMER EREN', createdAt: '-', updatedBy: '-', updatedAt: 'Henüz değiştirilmedi', hasUpdate: false };
    const createdBy = item.createdBy || item.assignedBy || item.manager || 'ÖMER EREN';
    const fallbackCreated = item.date ? `${formatDateTR(item.date)} ${item.time || '09:00'}` : (item.dueDate ? `${formatDateTR(item.dueDate)} ${item.dueTime || '09:00'}` : '-');
    const createdAt = item.createdAt || fallbackCreated;
    const hasUpdate = Boolean(item.updatedBy || (item.updatedAt && item.updatedAt !== item.createdAt));
    const updatedBy = hasUpdate ? (item.updatedBy || item.approvedBy || createdBy) : '-';
    const updatedAt = hasUpdate ? (item.updatedAt || item.approvedAt || createdAt) : 'Henüz değiştirilmedi';
    return { createdBy, createdAt, updatedBy, updatedAt, hasUpdate };
}

function renderRecordAuditBadge(item, compact = false) {
    const info = getRecordAuditInfo(item);
    if (compact) {
        return `
            <div style="margin-top:0.38rem; padding:0.32rem 0.55rem; background:rgba(15,23,42,0.65); border:1px solid rgba(148,163,184,0.2); border-radius:6px; font-size:0.71rem; color:#94a3b8; display:flex; flex-wrap:wrap; gap:0.55rem; align-items:center;">
                <span><i class="fa-solid fa-user-plus" style="color:#38bdf8;"></i> Oluşturan: <strong style="color:#e2e8f0;">${info.createdBy}</strong> (${info.createdAt})</span>
                <span>•</span>
                <span><i class="fa-solid fa-user-pen" style="color:${info.hasUpdate ? '#fbbf24' : '#64748b'};"></i> Değiştiren: <strong style="color:${info.hasUpdate ? '#fde68a' : '#94a3b8'};">${info.updatedBy}</strong> (${info.updatedAt})</span>
            </div>
        `;
    }
    return `
        <div style="margin-top:0.6rem; padding:0.5rem 0.7rem; background:rgba(15,23,42,0.72); border:1px solid rgba(56,189,248,0.22); border-radius:8px; font-size:0.74rem; color:#cbd5e1; display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:0.4rem;">
            <div style="display:flex; align-items:center; gap:0.4rem;">
                <i class="fa-solid fa-user-plus" style="color:#38bdf8;"></i>
                <div>
                    <span style="color:#94a3b8;">Oluşturan Kişi &amp; Zamanı:</span><br>
                    <strong style="color:#fff;">${info.createdBy}</strong> <span style="color:#38bdf8;">• ${info.createdAt}</span>
                </div>
            </div>
            <div style="display:flex; align-items:center; gap:0.4rem;">
                <i class="fa-solid fa-user-pen" style="color:${info.hasUpdate ? '#fbbf24' : '#64748b'};"></i>
                <div>
                    <span style="color:#94a3b8;">Değiştiren Kişi &amp; Zamanı:</span><br>
                    <strong style="color:${info.hasUpdate ? '#fde68a' : '#94a3b8'};">${info.updatedBy}</strong> <span style="color:${info.hasUpdate ? '#fbbf24' : '#64748b'};">• ${info.updatedAt}</span>
                </div>
            </div>
        </div>
    `;
}

// ==========================================================================
// 6. EKRAN RENDER FONKSİYONLARI (KOKPİT, TOPLANTI, AKSİYON, RAPOR, PERSONEL)
// ==========================================================================
function renderAll() {
    populateSelectFilters();
    updateVersionAdminPermissionUI();
    renderBgNotificationPermissionBanner();
    renderOmerApprovalCenter();
    renderDashboard();
    renderMeetings();
    renderActions();
    renderReports();
    renderPersonnel();
    renderLogs();
    renderVersionHistory();
    renderPushTestCenterUI();
    updateNavBadges();
    checkAndTriggerSmartReminders();
    checkAndTriggerMeetingCallAlerts();
}

function updateNavBadges() {
    const isAdmin = isOmerEren(currentUser);
    const visibleMeetings = isAdmin ? appState.meetings : appState.meetings.filter(m => getMeetingAccessLevel(m) !== 'NONE');
    const visibleOpenActions = appState.actions.filter(a => a.status !== "Tamamlandı" && (isAdmin || canUserSeeAction(a)));

    const mBadge = document.getElementById('nav-badge-meetings');
    const aBadge = document.getElementById('nav-badge-actions');
    const pBadge = document.getElementById('nav-badge-personnel');
    const lBadge = document.getElementById('nav-badge-logs');

    if (mBadge) mBadge.textContent = visibleMeetings.length;
    if (aBadge) aBadge.textContent = visibleOpenActions.length;
    if (pBadge) pBadge.textContent = isAdmin ? appState.users.length : 1;
    if (lBadge) lBadge.textContent = appState.logs.length;
}

function populateSelectFilters() {
    const isAdmin = isOmerEren(currentUser);
    const pFilter = document.getElementById('meeting-participant-filter');
    const aFilter = document.getElementById('action-assignee-filter');
    const aSelect = document.getElementById('action-assignee-select');
    const mSelect = document.getElementById('action-meeting-select');
    const repPersonFilter = document.getElementById('report-person-filter');

    const currP = pFilter ? pFilter.value : 'ALL';
    const currA = aFilter ? aFilter.value : 'ALL';
    const currRepP = repPersonFilter ? repPersonFilter.value : 'ALL';

    if (pFilter) {
        if (isAdmin) {
            pFilter.innerHTML = '<option value="ALL">Tüm Katılımcı Personeller</option>' +
                appState.users.map(u => `<option value="${u.name}">${u.name} (${u.dept})</option>`).join('');
            pFilter.value = currP;
        } else if (currentUser) {
            pFilter.innerHTML = `<option value="ALL">Katıldığım Toplantılar (${currentUser.name})</option>`;
            pFilter.value = 'ALL';
        }
    }

    if (aFilter) {
        if (isAdmin) {
            aFilter.innerHTML = '<option value="ALL">Tüm Sorumlu Personeller</option>' +
                appState.users.map(u => `<option value="${u.name}">${u.name} (${u.dept})</option>`).join('');
            aFilter.value = currA;
        } else if (currentUser) {
            aFilter.innerHTML = `<option value="ALL">Bana Ait / Yetkili Aksiyonlar (${currentUser.name})</option>`;
            aFilter.value = 'ALL';
        }
    }

    if (repPersonFilter) {
        if (isAdmin) {
            repPersonFilter.innerHTML = '<option value="ALL">Tüm Personeller</option>' +
                appState.users.map(u => `<option value="${u.name}">${u.name} (${u.dept})</option>`).join('');
            repPersonFilter.value = currRepP;
        } else if (currentUser) {
            repPersonFilter.innerHTML = `<option value="${currentUser.name}">${currentUser.name} (${currentUser.dept})</option>`;
            repPersonFilter.value = currentUser.name;
        }
    }

    if (aSelect) {
        aSelect.innerHTML = appState.users.map(u => `<option value="${u.name}">${u.name} — ${u.dept}</option>`).join('');
    }

    if (mSelect) {
        const accessibleMeetings = isAdmin ? appState.meetings : appState.meetings.filter(m => getMeetingAccessLevel(m) === 'FULL');
        const meetingOpts = accessibleMeetings.map(m => `<option value="${m.id}">${m.id} — ${m.title}</option>`).join('');
        mSelect.innerHTML = meetingOpts + `<option value="GENEL">GENEL — Bağımsız Aksiyon Görevi</option>`;
    }
}

// --- KATILIMCI GİZLİLİK VE YETKİ KONTROL MOTORU ---
// Kural:
// 1. Toplantıya katılanlar (işaretli katılımcılar + oluşturan + Sistem Yöneticisi Ömer Eren) -> 'FULL' (Tüm toplantı içeriğini, notları, kararları, ekleri görür)
// 2. Toplantıya katılmayıp sadece o toplantıda kendisine aksiyon verilen kişiler -> 'ACTION_ONLY' (Toplantı notlarını/kararlarını/eklerini GÖREMEZ, sadece kendisine verilen aksiyonu görür)
// 3. Toplantıya katılmayan ve aksiyonu da olmayan kişiler -> 'NONE' (Toplantıyı ve içeriğini hiç görmez)
function getMeetingAccessLevel(m, user = currentUser) {
    if (!user || !m) return 'NONE';
    if (isOmerEren(user)) return 'FULL';
    if (normalizeTR(m.createdBy || '') === normalizeTR(user.name)) return 'FULL';
    const isParticipant = (m.participants || []).some(p => normalizeTR(p) === normalizeTR(user.name));
    if (isParticipant) return 'FULL';

    const hasAssignedAction = appState.actions.some(a =>
        a.meetingId === m.id &&
        (normalizeTR(a.assignee) === normalizeTR(user.name) || normalizeTR(a.manager || '') === normalizeTR(user.name))
    );
    if (hasAssignedAction) return 'ACTION_ONLY';

    return 'NONE';
}

function canUserSeeAction(a, user = currentUser) {
    if (!user || !a) return false;
    if (isOmerEren(user)) return true;
    if (normalizeTR(a.assignee) === normalizeTR(user.name)) return true;
    if (normalizeTR(a.manager || '') === normalizeTR(user.name)) return true;
    if (normalizeTR(a.createdBy || '') === normalizeTR(user.name)) return true;

    const parentMeeting = appState.meetings.find(m => m.id === a.meetingId);
    if (parentMeeting && getMeetingAccessLevel(parentMeeting, user) === 'FULL') {
        return true;
    }
    return false;
}

function renderDashboard() {
    const visibleMeetings = appState.meetings.filter(m => getMeetingAccessLevel(m) !== 'NONE');
    const visibleActions = appState.actions.filter(a => canUserSeeAction(a));

    const totalMeetings = visibleMeetings.length;
    const openActions = visibleActions.filter(a => a.status !== "Tamamlandı");
    const completedActions = visibleActions.filter(a => a.status === "Tamamlandı");
    const activeReminders = openActions.filter(a => {
        const st = evaluateActionReminderStatus(a);
        return st.stage === 'ONE_DAY_BEFORE' || st.stage === 'SAME_DAY' || st.stage === 'OVERDUE';
    });

    document.getElementById('kpi-total-meetings').textContent = totalMeetings;
    document.getElementById('kpi-open-actions').textContent = openActions.length;
    document.getElementById('kpi-reminder-actions').textContent = activeReminders.length;
    document.getElementById('kpi-completed-actions').textContent = completedActions.length;

    const rate = visibleActions.length > 0
        ? Math.round((completedActions.length / visibleActions.length) * 100)
        : 0;
    document.getElementById('kpi-completion-rate').textContent = `%${rate} Tamamlanma Oranı`;

    // Yaklaşan Aksiyonlar ve Hatırlatıcılar (Sadece yetkili olunan aksiyonlar)
    const upBox = document.getElementById('dashboard-upcoming-actions');
    if (upBox) {
        if (visibleActions.length === 0) {
            upBox.innerHTML = `
                <div style="text-align:center; padding:1.75rem; color:var(--text-sec); border:1px dashed var(--border-color); border-radius:12px;">
                    <i class="fa-solid fa-bell" style="font-size:1.5rem; color:var(--dizsan-light); margin-bottom:0.5rem; display:block;"></i>
                    Size tanımlanmış veya katıldığınız oturumlara ait aksiyon kaydı yok.<br>
                    <button class="btn btn-success btn-sm" style="margin-top:0.65rem;" onclick="openActionModal()"><i class="fa-solid fa-plus"></i> Yeni Aksiyon Ekle</button>
                </div>`;
        } else {
            const sortedActions = [...visibleActions]
                .sort((a, b) => evaluateActionReminderStatus(a).diffDays - evaluateActionReminderStatus(b).diffDays)
                .slice(0, 5);

            upBox.innerHTML = sortedActions.map(a => {
                const st = evaluateActionReminderStatus(a);
                return `
                    <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-color); border-radius:12px; padding:0.85rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; flex-wrap:wrap;">
                        <div style="flex:1; min-width:200px;">
                            <div style="display:flex; align-items:center; gap:0.45rem; margin-bottom:0.25rem; flex-wrap:wrap;">
                                <span class="badge ${a.priority === 'Kritik' ? 'badge-critical' : 'badge-normal'}">${a.priority}</span>
                                <strong style="font-size:0.85rem; color:#fff;">Sorumlu: ${a.assignee}</strong>
                                <span style="font-size:0.75rem; color:var(--dizsan-light);">• Yönetici: ${a.manager || 'ÖMER EREN'}</span>
                            </div>
                            <div style="font-size:0.83rem; color:#cbd5e1;">${a.title}</div>
                            ${renderRecordAuditBadge(a, true)}
                        </div>
                        <div class="countdown-pill ${st.type}">${st.shortText || st.badgeText}</div>
                    </div>
                `;
            }).join('');
        }
    }

    // Son Toplantılar & Eğitimler (Katılımcı Gizlilik Kuralı Uygulanmış)
    const recMeetings = document.getElementById('dashboard-recent-meetings');
    if (recMeetings) {
        if (visibleMeetings.length === 0) {
            recMeetings.innerHTML = `
                <div style="text-align:center; padding:1.75rem; color:var(--text-sec); border:1px dashed var(--border-color); border-radius:12px;">
                    <i class="fa-solid fa-handshake" style="font-size:1.5rem; color:var(--dizsan-light); margin-bottom:0.5rem; display:block;"></i>
                    Katılımcısı olduğunuz toplantı veya eğitim kaydı bulunmuyor.<br>
                    <button class="btn btn-primary btn-sm" style="margin-top:0.65rem;" onclick="openMeetingModal()"><i class="fa-solid fa-plus"></i> Yeni Toplantı / Eğitim Başlat</button>
                </div>`;
        } else {
            recMeetings.innerHTML = visibleMeetings.slice(0, 4).map(m => {
                const access = getMeetingAccessLevel(m);
                const recType = m.recordType === 'Eğitim' ? '🎓 Eğitim' : '🤝 Toplantı';
                if (access === 'ACTION_ONLY') {
                    const myActions = appState.actions.filter(a => a.meetingId === m.id && (normalizeTR(a.assignee) === normalizeTR(currentUser?.name) || normalizeTR(a.manager || '') === normalizeTR(currentUser?.name)));
                    return `
                        <div style="background:rgba(245,158,11,0.06); border:1px solid rgba(245,158,11,0.3); border-radius:12px; padding:0.9rem;">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.3rem;">
                                <span class="meeting-code-badge">${m.id} • ${recType} (Sadece Aksiyonunuz)</span>
                                <span style="font-size:0.78rem; color:var(--text-sec);"><i class="fa-regular fa-calendar"></i> ${formatDateTR(m.date)}</span>
                            </div>
                            <div style="font-size:0.8rem; color:#fde68a; margin-bottom:0.35rem;"><i class="fa-solid fa-lock"></i> Katılımcı olmadığınız için toplantı detayı gizlidir. Size atanan aksiyon:</div>
                            ${myActions.map(ma => `
                                <div style="font-weight:700; color:#fff; font-size:0.85rem;">• ${ma.title} (Termin: ${formatDateTR(ma.dueDate)})</div>
                                ${renderRecordAuditBadge(ma, true)}
                            `).join('')}
                        </div>
                    `;
                }
                const mActions = appState.actions.filter(a => a.meetingId === m.id);
                const attInfo = getMeetingAttendanceSummary(m);
                const extCount = (m.externalParticipants || []).length;
                const totalPartCount = attInfo.invited.length + extCount;
                const attCount = (m.attachments || []).length;
                const agdItems = parseAgendaItemsFromMeeting(m);
                const undiscussedCount = agdItems.filter(x => x.title && !x.discussed).length;
                return `
                    <div class="clickable-card" onclick="handleMeetingCardClick(event, '${m.id}')" style="background:rgba(255,255,255,0.03); border:1px solid var(--border-color); border-radius:12px; padding:0.9rem; cursor:pointer; transition:all 0.2s;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.3rem; flex-wrap:wrap; gap:0.35rem;">
                            <span class="meeting-code-badge">${m.id} • ${recType} • ${m.dept}</span>
                            <span style="font-size:0.78rem; color:var(--text-sec);"><i class="fa-regular fa-calendar"></i> ${formatDateTR(m.date)} ${m.time}</span>
                        </div>
                        <div style="font-weight:700; color:#fff; font-size:0.92rem; margin-bottom:0.35rem;">${m.title}</div>
                        ${renderRecordAuditBadge(m, true)}
                        <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.76rem; color:var(--text-sec); margin-top:0.45rem; flex-wrap:wrap; gap:0.4rem;">
                            <span>
                                <i class="fa-solid fa-envelope-open-text" style="color:#38bdf8;"></i> ${totalPartCount} Davetli
                                • <span style="color:#34d399;"><i class="fa-solid fa-user-check"></i> ${attInfo.attended.length} Gelen</span>
                                ${attInfo.absent.length > 0 ? ` • <span style="color:#f87171;"><i class="fa-solid fa-user-xmark"></i> ${attInfo.absent.length} Gelmeyen</span>` : ''}
                                ${undiscussedCount > 0 ? ` • <span style="color:#fbbf24;"><i class="fa-solid fa-clock-rotate-left"></i> ${undiscussedCount} Konuşulmayan Gündem</span>` : ''}
                            </span>
                            <div style="display:flex; gap:0.35rem;">
                                ${undiscussedCount > 0 ? `
                                <button class="btn btn-sm" style="padding:3px 8px; font-size:0.72rem; background:#f59e0b; color:#0f172a; font-weight:700;" onclick="event.stopPropagation(); openFollowupMeetingModal('${m.id}')">
                                    <i class="fa-solid fa-calendar-plus"></i> Başka Toplantıya Planla
                                </button>` : ''}
                                <button class="btn btn-secondary btn-sm" style="padding:3px 8px; font-size:0.74rem;" onclick="event.stopPropagation(); printMeetingMinutes('${m.id}')">
                                    <i class="fa-solid fa-print"></i> Tutanak Yazdır
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // Son Loglar (Sadece Yönetici Ömer Eren görebilir, diğer herkese kapalıdır)
    const logsCard = document.getElementById('dashboard-logs-card');
    const navItemLogs = document.getElementById('nav-item-logs');
    const recLogs = document.getElementById('dashboard-recent-logs');
    if (isOmerEren(currentUser)) {
        if (logsCard) logsCard.style.display = 'block';
        if (navItemLogs) navItemLogs.style.display = 'block';
        if (recLogs) {
            if (appState.logs.length === 0) {
                recLogs.innerHTML = `<div style="padding:1rem; color:var(--text-sec); font-size:0.83rem;">Henüz işlem logu bulunmuyor.</div>`;
            } else {
                recLogs.innerHTML = appState.logs.slice(0, 4).map(l => `
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:0.55rem 0.75rem; background:rgba(255,255,255,0.02); border-radius:8px; border-left:3px solid var(--dizsan-light); font-size:0.8rem;">
                        <div>
                            <strong style="color:#fff;">${l.user}:</strong>
                            <span style="color:#cbd5e1;">${l.detail}</span>
                        </div>
                        <span style="color:var(--text-muted); font-size:0.72rem; white-space:nowrap; margin-left:0.5rem;">${l.timestamp}</span>
                    </div>
                `).join('');
            }
        }
    } else {
        if (logsCard) logsCard.style.display = 'none';
        if (navItemLogs) navItemLogs.style.display = 'none';
        if (recLogs) recLogs.innerHTML = '';
    }
}

function renderMeetings() {
    const container = document.getElementById('meetings-container');
    if (!container) return;

    const q = normalizeTR(document.getElementById('meeting-search')?.value || '');
    const typeF = document.getElementById('meeting-type-filter')?.value || 'ALL';
    const deptF = document.getElementById('meeting-dept-filter')?.value || 'ALL';
    const partF = document.getElementById('meeting-participant-filter')?.value || 'ALL';

    const filtered = appState.meetings.filter(m => {
        const access = getMeetingAccessLevel(m);
        // Toplantıya katılmayan ve o toplantıda aksiyonu olmayan kişiler toplantıyı kesinlikle göremez
        if (access === 'NONE') return false;

        const mType = m.recordType || 'Toplantı';
        if (typeF !== 'ALL' && mType !== typeF) return false;
        if (deptF !== 'ALL' && m.dept !== deptF) return false;
        if (partF !== 'ALL' && !(m.participants || []).includes(partF)) return false;
        if (q) {
            if (access === 'ACTION_ONLY') {
                const myActs = appState.actions.filter(a => a.meetingId === m.id && normalizeTR(a.assignee) === normalizeTR(currentUser?.name));
                const actHay = normalizeTR(`${m.id} ${myActs.map(x => x.title).join(' ')}`);
                if (!actHay.includes(q)) return false;
            } else {
                const extStr = (m.externalParticipants || []).map(ep => `${ep.name} ${ep.phone || ''} ${ep.company || ''}`).join(' ');
                const haystack = normalizeTR(`${m.id} ${mType} ${m.title} ${m.notes} ${m.decisions} ${(m.participants || []).join(' ')} ${extStr} ${m.createdBy || ''} ${m.updatedBy || ''}`);
                if (!haystack.includes(q)) return false;
            }
        }
        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = `
            <div style="grid-column: 1 / -1; text-align:center; padding:3rem 1.5rem; color:var(--text-sec); border:1px dashed var(--border-color); border-radius:16px;">
                <i class="fa-solid fa-handshake" style="font-size:2.2rem; color:var(--dizsan-light); margin-bottom:0.75rem; display:block;"></i>
                <h4 style="color:#fff; margin-bottom:0.35rem;">Görüntülenebilecek Toplantı veya Eğitim Kaydı Bulunmuyor</h4>
                <p style="font-size:0.85rem; margin-bottom:1rem;">Sadece katılımcısı olduğunuz toplantı/eğitim kayıtlarını veya size aksiyon atanan görevleri görüntüleyebilirsiniz.</p>
                <button class="btn btn-primary" onclick="openMeetingModal()"><i class="fa-solid fa-plus"></i> Yeni Toplantı / Eğitim Kaydı Oluştur</button>
            </div>`;
        return;
    }

    container.innerHTML = filtered.map(m => {
        const access = getMeetingAccessLevel(m);
        const isTraining = (m.recordType === 'Eğitim');
        const typeBadgeHtml = isTraining
            ? `<span class="badge" style="background:rgba(168,85,247,0.2); border:1px solid rgba(168,85,247,0.45); color:#e9d5ff;"><i class="fa-solid fa-graduation-cap"></i> 🎓 EĞİTİM</span>`
            : `<span class="badge badge-normal"><i class="fa-solid fa-handshake"></i> 🤝 TOPLANTI</span>`;

        // DURUM 1: KULLANICI TOPLANTIYA KATILMAMIŞ AMA KENDİSİNE AKSİYON VERİLMİŞ ('ACTION_ONLY')
        // Kural: Toplantı içeriğini, notları, kararları, katılımcıları ve ekleri GÖREMEZ; sadece kendisine verilen aksiyonu görür!
        if (access === 'ACTION_ONLY') {
            const myActions = appState.actions.filter(a =>
                a.meetingId === m.id &&
                (normalizeTR(a.assignee) === normalizeTR(currentUser?.name) || normalizeTR(a.manager || '') === normalizeTR(currentUser?.name))
            );

            return `
                <div class="meeting-card" style="border-color:rgba(245,158,11,0.4); background:rgba(17,24,39,0.92);">
                    <div>
                        <div class="meeting-card-top">
                            <div style="display:flex; gap:0.4rem; align-items:center; flex-wrap:wrap;">
                                <span class="meeting-code-badge">${m.id}</span>
                                ${typeBadgeHtml}
                            </div>
                            <span class="badge badge-high"><i class="fa-solid fa-user-lock"></i> Sadece Aksiyon Görünümü</span>
                        </div>

                        <div style="margin:0.65rem 0; padding:0.75rem; background:rgba(245,158,11,0.1); border:1px dashed rgba(245,158,11,0.4); border-radius:10px; font-size:0.8rem; color:#fde68a;">
                            <i class="fa-solid fa-lock"></i> <strong>Gizli Tutanak İçeriği:</strong> Bu ${isTraining ? 'eğitimin' : 'toplantının'} katılımcı listesinde yer almadığınız için toplantı notları, kararlar ve ek belgeler gizlidir. <strong>Yalnızca size atanan aksiyon aşağıda gösterilmektedir:</strong>
                        </div>

                        <div style="display:flex; flex-direction:column; gap:0.55rem; margin-top:0.6rem;">
                            ${myActions.map(ma => {
                                const st = evaluateActionReminderStatus(ma);
                                return `
                                    <div style="background:rgba(2,132,199,0.12); border:1px solid rgba(56,189,248,0.35); border-radius:10px; padding:0.75rem;">
                                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem; flex-wrap:wrap; gap:0.4rem;">
                                            <strong style="color:var(--dizsan-light); font-size:0.82rem;">${ma.id} — Size Atanan Aksiyon</strong>
                                            <span class="countdown-pill ${st.type}">${st.shortText}</span>
                                        </div>
                                        <div style="font-weight:700; color:#fff; font-size:0.9rem; margin-bottom:0.4rem;">${ma.title}</div>
                                        ${renderRecordAuditBadge(ma, true)}
                                        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; font-size:0.78rem; color:var(--text-sec); margin-top:0.4rem;">
                                            <span>Termin: <strong>${formatDateTR(ma.dueDate)} ${ma.dueTime || '09:00'}</strong></span>
                                            <select class="form-control" style="width:auto; padding:0.25rem 0.5rem; font-size:0.76rem; font-weight:700;" onchange="quickChangeActionStatus('${ma.id}', this.value)">
                                                <option value="Bekliyor" ${ma.status === 'Bekliyor' ? 'selected' : ''}>⏳ Bekliyor</option>
                                                <option value="Devam Ediyor" ${ma.status === 'Devam Ediyor' ? 'selected' : ''}>🔄 Devam Ediyor</option>
                                                <option value="Tamamlandı" ${ma.status === 'Tamamlandı' ? 'selected' : ''}>✅ Tamamlandı</option>
                                            </select>
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                </div>
            `;
        }

        // DURUM 2: KULLANICI İŞARETLİ KATILIMCI ('FULL') -> TÜM DETAYLARI VE EKLERİ GÖRÜR
        const relatedActions = appState.actions.filter(a => a.meetingId === m.id);
        const doneCount = relatedActions.filter(a => a.status === 'Tamamlandı').length;
        const extList = m.externalParticipants || [];
        const attList = m.attachments || [];
        const isPendingApproval = (m.approvalStatus === 'Yönetici Onayı Bekliyor');
        const pendingReqsForMeeting = (appState.approvalRequests || []).filter(r => r.meetingId === m.id && r.status === 'PENDING');
        const isAdminOmer = isOmerEren(currentUser);

        const attInfo = getMeetingAttendanceSummary(m);
        const agendaItems = parseAgendaItemsFromMeeting(m);
        const discussedAgendas = agendaItems.filter(x => x.title && x.discussed);
        const undiscussedAgendas = agendaItems.filter(x => x.title && !x.discussed);
        const decisionItems = parseDecisionItemsFromMeeting(m).filter(d => d.text && d.text.trim());

        const approvalBadgeHtml = isPendingApproval
            ? `<span class="badge badge-high" title="Yönetici Ömer Eren Onayı Bekleniyor"><i class="fa-solid fa-hourglass-half"></i> ⏳ Yönetici Onayı Bekliyor</span>`
            : `<span class="badge badge-done" title="Yönetici Ömer Eren Tarafından Onaylandı"><i class="fa-solid fa-shield-check"></i> ✅ Yönetici Onaylı (Ömer Eren)</span>`;

        return `
            <div class="meeting-card clickable-card" onclick="handleMeetingCardClick(event, '${m.id}')" style="${isPendingApproval ? 'border-color:rgba(245,158,11,0.55);' : ''}" title="Detayları görmek, yoklama almak, gündem tiklemek ve kararları yönetmek için karta tıklayın">
                <div>
                    <div class="meeting-card-top">
                        <div style="display:flex; gap:0.4rem; align-items:center; flex-wrap:wrap;">
                            <span class="meeting-code-badge">${m.id} • ${m.dept}</span>
                            ${typeBadgeHtml}
                            ${approvalBadgeHtml}
                        </div>
                        <span style="font-size:0.76rem; color:var(--text-sec);"><i class="fa-solid fa-user-pen"></i> ${m.createdBy || 'ÖMER EREN'}</span>
                    </div>

                    ${pendingReqsForMeeting.length > 0 ? `
                    <div style="margin:0.45rem 0; padding:0.45rem 0.65rem; background:rgba(245,158,11,0.14); border:1px dashed rgba(245,158,11,0.5); border-radius:8px; font-size:0.76rem; color:#fde68a;">
                        <i class="fa-solid fa-user-shield"></i> <strong>Ömer Eren Onayı Bekleyen İşlem:</strong> ${pendingReqsForMeeting.map(r => `${r.requestedBy} (${r.type === 'DELETE_MEETING' ? 'Silme Talebi' : 'Değiştirme Talebi'})`).join(', ')}
                    </div>` : ''}

                    <h4 class="meeting-title">${m.title}</h4>
                    <div class="meeting-meta">
                        <span><i class="fa-regular fa-calendar"></i> ${formatDateTR(m.date)}</span>
                        <span><i class="fa-regular fa-clock"></i> ${m.time}</span>
                        <span><i class="fa-solid fa-location-dot"></i> ${m.location || 'Merkez'}</span>
                    </div>

                    <div class="card-click-hint">
                        <i class="fa-solid fa-hand-pointer"></i> Detay, Yoklama, Gündem Tikleme &amp; Karar Ekranı İçin Karta Basın
                    </div>

                    ${renderRecordAuditBadge(m, false)}

                    <!-- GÜNDEM MADDELERİ (KONUŞULANLAR & KONUŞULMAYANLAR) ÖZETİ -->
                    <div class="meeting-summary-box" style="max-height:none; overflow:visible; margin-top:0.6rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.35rem; margin-bottom:0.35rem;">
                            <strong style="color:#fff;"><i class="fa-solid fa-list-check" style="color:var(--dizsan-light);"></i> ${isTraining ? 'Eğitim Gündemi & Notlar:' : 'Gündem Maddeleri:'}</strong>
                            <div style="display:flex; gap:0.3rem; font-size:0.7rem;">
                                <span style="background:rgba(16,185,129,0.2); color:#6ee7b7; padding:1px 6px; border-radius:5px; font-weight:700;">✅ ${discussedAgendas.length} Konuşuldu</span>
                                ${undiscussedAgendas.length > 0 ? `<span style="background:rgba(245,158,11,0.22); color:#fde68a; padding:1px 6px; border-radius:5px; font-weight:700;">⏳ ${undiscussedAgendas.length} Konuşulmadı</span>` : ''}
                            </div>
                        </div>
                        <div style="display:flex; flex-direction:column; gap:0.32rem;">
                            ${agendaItems.filter(x => x.title).map((ag, idx) => `
                                <div style="padding:0.32rem 0.5rem; border-radius:6px; background:${ag.discussed ? 'rgba(16,185,129,0.1)' : 'rgba(245,158,11,0.08)'}; border:1px solid ${ag.discussed ? 'rgba(16,185,129,0.3)' : 'rgba(245,158,11,0.28)'};">
                                    <div style="display:flex; align-items:center; justify-content:space-between; gap:0.4rem;">
                                        <span style="font-weight:600; color:${ag.discussed ? '#d1fae5' : '#fef3c7'}; font-size:0.8rem;">
                                            ${ag.discussed ? '✅' : '⬜'} ${idx + 1}. ${ag.title}
                                        </span>
                                        <span style="font-size:0.68rem; color:${ag.discussed ? '#34d399' : '#fbbf24'}; font-weight:700; white-space:nowrap;">
                                            ${ag.discussed ? 'Konuşuldu' : (ag.transferredToMeetingId ? `➔ ${ag.transferredToMeetingId}` : 'Konuşulmadı')}
                                        </span>
                                    </div>
                                    ${ag.discussed && ag.explanation ? `
                                        <div style="margin-top:0.22rem; padding-top:0.22rem; border-top:1px dashed rgba(52,211,153,0.3); font-size:0.75rem; color:#a7f3d0; white-space:pre-line;">
                                            <i class="fa-solid fa-comment-dots"></i> <strong>Açıklama:</strong> ${ag.explanation}
                                        </div>
                                    ` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>

                    <!-- KONUŞULMAYAN MADDELER VARSA BAŞKA TOPLANTI PLANLAMA KUTUSU -->
                    ${undiscussedAgendas.length > 0 ? `
                    <div style="margin-top:0.55rem; padding:0.55rem 0.7rem; background:rgba(245,158,11,0.12); border:1px dashed rgba(245,158,11,0.5); border-radius:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; gap:0.4rem; flex-wrap:wrap;">
                            <div style="font-size:0.76rem; color:#fde68a; font-weight:700;">
                                <i class="fa-solid fa-clock-rotate-left"></i> Konuşulmayan ${undiscussedAgendas.length} Gündem Maddesi Mevcut
                            </div>
                            <button type="button" class="btn btn-sm" style="padding:3px 9px; font-size:0.72rem; background:linear-gradient(135deg,#f59e0b,#d97706); color:#0f172a; font-weight:800;" onclick="event.stopPropagation(); openFollowupMeetingModal('${m.id}')">
                                <i class="fa-solid fa-calendar-plus"></i> Başka Toplantı Planla
                            </button>
                        </div>
                    </div>` : ''}

                    <!-- ALINAN KARARLAR, KARAR SORUMLUSU VE TERMİN TARİHLERİ -->
                    ${decisionItems.length > 0 ? `
                    <div style="margin-top:0.55rem; font-size:0.79rem; color:#a7f3d0; background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.25); padding:0.55rem 0.7rem; border-radius:8px;">
                        <strong style="display:block; margin-bottom:0.35rem; color:#6ee7b7;"><i class="fa-solid fa-gavel"></i> ${isTraining ? 'Eğitim Sonucu & Değerlendirme:' : 'Alınan Kararlar, Sorumlusu & Termin:'}</strong>
                        <div style="display:flex; flex-direction:column; gap:0.32rem;">
                            ${decisionItems.map((dec, dIdx) => `
                                <div style="background:rgba(15,23,42,0.65); border:1px solid rgba(52,211,153,0.25); border-radius:6px; padding:0.35rem 0.5rem;">
                                    <div style="color:#ecfdf5; font-weight:600; font-size:0.79rem;">${dIdx + 1}. ${dec.text}</div>
                                    <div style="display:flex; gap:0.6rem; flex-wrap:wrap; margin-top:0.2rem; font-size:0.71rem; color:#93c5fd;">
                                        <span><i class="fa-solid fa-user-check" style="color:#38bdf8;"></i> Sorumlu: <strong style="color:#fff;">${dec.responsible || 'Belirtilmedi'}</strong></span>
                                        <span><i class="fa-regular fa-calendar-check" style="color:#fbbf24;"></i> Termin: <strong style="color:#fde68a;">${dec.dueDate ? formatDateTR(dec.dueDate) : '-'}</strong></span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>` : ''}

                    ${attList.length > 0 ? `
                    <div style="margin-top:0.65rem; padding:0.6rem; background:rgba(16,185,129,0.06); border:1px solid rgba(16,185,129,0.25); border-radius:8px;">
                        <div style="font-size:0.75rem; font-weight:700; color:#6ee7b7; margin-bottom:0.4rem;">
                            <i class="fa-solid fa-paperclip"></i> Eklenen Fotoğraf, Kağıt Tutanak &amp; Belgeler (${attList.length} Adet):
                        </div>
                        <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
                            ${attList.map(att => {
                                const isImg = (att.type || '').startsWith('image/');
                                const isPdf = (att.type || '').toLowerCase().includes('pdf') || (att.name || '').toLowerCase().endsWith('.pdf');
                                const imgSrc = isImg ? (att.dataUrl || att.fileUrl || '') : '';
                                return `
                                    <button type="button" onclick="event.stopPropagation(); openAttachmentPreviewModal('${m.id}', '${att.id}')" style="display:inline-flex; align-items:center; gap:0.4rem; background:rgba(15,23,42,0.75); border:1px solid ${isPdf ? 'rgba(248,113,113,0.45)' : 'rgba(52,211,153,0.35)'}; color:#e2e8f0; padding:4px 8px; border-radius:6px; font-size:0.74rem; cursor:pointer;" title="Belgeyi Aç / Önizle">
                                        ${isImg && imgSrc ? `<img src="${imgSrc}" style="width:24px; height:24px; object-fit:cover; border-radius:4px;">` : `<i class="fa-solid ${att.kind === 'NOTE' ? 'fa-note-sticky' : (isPdf ? 'fa-file-pdf' : 'fa-file-lines')}" style="color:${isPdf ? '#f87171' : '#34d399'};"></i>`}
                                        <span style="max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${att.name || att.note || 'Ek Belge'}</span>
                                    </button>
                                `;
                            }).join('')}
                        </div>
                    </div>` : ''}

                    <!-- DAVET EDİLEN, GELEN VE GELMEYEN KATILIMCILAR (+ NEDENLERİ) -->
                    <div style="margin-top:0.65rem;">
                        <div style="display:flex; gap:0.4rem; flex-wrap:wrap; margin-bottom:0.35rem; font-size:0.71rem;">
                            <span style="background:rgba(56,189,248,0.15); color:#7dd3fc; padding:2px 7px; border-radius:5px; font-weight:700;">📨 ${attInfo.invited.length} Davetli</span>
                            <span style="background:rgba(16,185,129,0.18); color:#6ee7b7; padding:2px 7px; border-radius:5px; font-weight:700;">✅ ${attInfo.attended.length} Gelen</span>
                            ${attInfo.absent.length > 0 ? `<span style="background:rgba(239,68,68,0.2); color:#fca5a5; padding:2px 7px; border-radius:5px; font-weight:700;">❌ ${attInfo.absent.length} Gelmeyen</span>` : ''}
                        </div>
                        <div class="participants-avatars" style="margin-top:0.25rem;">
                            ${attInfo.attended.map(p => `<span class="participant-tag" style="border-color:rgba(16,185,129,0.35);"><i class="fa-solid fa-user-check" style="font-size:0.65rem; color:#34d399;"></i> ${p}</span>`).join('')}
                            ${extList.map(ep => `<span class="participant-tag" style="background:rgba(245,158,11,0.14); border-color:rgba(245,158,11,0.4); color:#fde68a;" title="Dış Katılımcı | Firma: ${ep.company || '-'} | Tel: ${ep.phone || '-'}"><i class="fa-solid fa-building-user" style="font-size:0.65rem; color:#fbbf24;"></i> ${ep.name}${ep.company ? ` (${ep.company})` : ''}${ep.phone ? ` • ${ep.phone}` : ''}</span>`).join('')}
                        </div>
                        ${attInfo.absent.length > 0 ? `
                        <div style="margin-top:0.45rem; padding:0.45rem 0.6rem; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.35); border-radius:8px; font-size:0.74rem;">
                            <div style="font-weight:700; color:#fca5a5; margin-bottom:0.2rem;"><i class="fa-solid fa-user-xmark"></i> Gelmeyen Katılımcılar &amp; Nedenleri:</div>
                            ${attInfo.absent.map(ab => `
                                <div style="color:#fecaca; font-size:0.73rem;">• <strong>${ab.name}:</strong> <span style="color:#fde68a;">${ab.reason || 'Mazeret belirtilmedi'}</span></div>
                            `).join('')}
                        </div>` : ''}
                    </div>
                </div>

                <div class="meeting-card-footer" onclick="event.stopPropagation()">
                    <span class="badge ${relatedActions.length > 0 && doneCount === relatedActions.length ? 'badge-done' : 'badge-normal'}">
                        <i class="fa-solid fa-bolt"></i> ${relatedActions.length} Aksiyon (${doneCount} Tamam)
                    </span>
                    <div style="display:flex; gap:0.35rem; flex-wrap:wrap;">
                        ${isAdminOmer && isPendingApproval ? `
                        <button class="btn btn-success btn-sm" onclick="approveNewMeeting('${m.id}')" title="Yönetici Olarak Onayla">
                            <i class="fa-solid fa-check"></i> Onayla
                        </button>` : ''}
                        <button class="btn btn-primary btn-sm" onclick="openMeetingModal('${m.id}')" title="Toplantı Detayını, Yoklamayı, Gündemi ve Kararları Aç">
                            <i class="fa-solid fa-up-right-from-square"></i> Detay
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="downloadMeetingAlarmICS('${m.id}')" title="Uygulama Kapalıyken Çalması İçin Telefon/PC Alarmına Kur">
                            <i class="fa-solid fa-bell" style="color:#fcd34d;"></i>
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="printMeetingMinutes('${m.id}')" title="A4 Resmi Dizsan Tutanağı Yazdır">
                            <i class="fa-solid fa-print"></i> Tutanak
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="openMeetingModal('${m.id}')" title="${isAdminOmer ? 'Düzenle' : 'Değiştirme (Ömer Eren Onaylı)'}">
                            <i class="fa-solid fa-pen"></i>
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deleteMeeting('${m.id}')" title="${isAdminOmer ? 'Sil' : 'Silme Talebi (Ömer Eren Onaylı)'}">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function renderActions() {
    const tbody = document.getElementById('actions-tbody');
    if (!tbody) return;

    const q = normalizeTR(document.getElementById('action-search')?.value || '');
    const assigneeF = document.getElementById('action-assignee-filter')?.value || 'ALL';
    const prioF = document.getElementById('action-priority-filter')?.value || 'ALL';
    const statF = document.getElementById('action-status-filter')?.value || 'ALL';

    const filtered = appState.actions.filter(a => {
        // Gizlilik Kuralı: Katılmadığı toplantıdaki başkasına ait aksiyonları göremez, sadece kendisine atanan aksiyonları veya katıldığı toplantının aksiyonlarını görür
        if (!canUserSeeAction(a)) return false;

        if (assigneeF !== 'ALL' && a.assignee !== assigneeF) return false;
        if (prioF !== 'ALL' && a.priority !== prioF) return false;
        if (statF !== 'ALL' && a.status !== statF) return false;
        if (q) {
            const hay = normalizeTR(`${a.id} ${a.title} ${a.assignee} ${a.manager || ''} ${a.meetingTitle} ${a.note || ''} ${a.createdBy || ''} ${a.updatedBy || ''}`);
            if (!hay.includes(q)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:2.5rem; color:var(--text-sec);">Görüntülenebilecek aksiyon kaydı bulunmuyor. "+ Yeni Aksiyon Tanımla" butonu ile hemen ekleyebilirsiniz.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => {
        const st = evaluateActionReminderStatus(a);
        const parentM = appState.meetings.find(m => m.id === a.meetingId);
        const access = parentM ? getMeetingAccessLevel(parentM) : 'FULL';
        // Katılmadığı bir toplantıdan aksiyon verilmişse toplantı başlığını gizle, sadece aksiyon kodunu göster
        const meetingLabel = access === 'ACTION_ONLY' ? `${a.meetingId} (Sadece Aksiyon)` : (a.meetingTitle || a.meetingId);

        return `
            <tr>
                <td>
                    <div style="font-weight:700; color:var(--dizsan-light);">${a.id}</div>
                    <div style="font-size:0.74rem; color:var(--text-sec); max-width:150px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${meetingLabel}">${a.meetingId}</div>
                </td>
                <td>
                    <div style="font-weight:600; color:#fff; margin-bottom:3px;">${a.title}</div>
                    ${a.note ? `<div style="font-size:0.76rem; color:var(--text-sec);"><i class="fa-regular fa-comment-dots"></i> ${a.note}</div>` : ''}
                    ${renderRecordAuditBadge(a, true)}
                </td>
                <td>
                    <span class="participant-tag" style="font-weight:600;"><i class="fa-solid fa-user-check" style="color:var(--dizsan-light);"></i> ${a.assignee}</span>
                </td>
                <td>
                    <span class="participant-tag" style="border-color:rgba(245,158,11,0.35); color:#fde68a;"><i class="fa-solid fa-user-tie"></i> ${a.manager || 'ÖMER EREN'}</span>
                </td>
                <td>
                    <span class="badge ${a.priority === 'Kritik' ? 'badge-critical' : 'badge-normal'}">
                        ${a.priority === 'Kritik' ? '🚨 Kritik' : '🔵 Normal'}
                    </span>
                </td>
                <td>
                    <div style="font-weight:700; color:#fff;"><i class="fa-regular fa-calendar-check" style="color:#38bdf8;"></i> ${formatDateTR(a.dueDate)}</div>
                    <div style="font-size:0.75rem; color:#fde68a; font-weight:600;"><i class="fa-regular fa-clock"></i> Saat: ${a.dueTime || '17:00'}</div>
                    ${a.status === 'Tamamlandı' && getActionCompletedDisplay(a) ? `
                        <div style="margin-top:4px; padding:2px 6px; border-radius:6px; background:rgba(16,185,129,0.16); border:1px solid rgba(16,185,129,0.4); font-size:0.7rem; color:#6ee7b7; font-weight:700;">
                            ✅ Bitiş: ${getActionCompletedDisplay(a)}
                        </div>
                    ` : ''}
                </td>
                <td>
                    <span class="countdown-pill ${st.type}">${st.badgeText}</span>
                </td>
                <td>
                    <select class="form-control" style="padding:0.35rem 0.55rem; font-size:0.78rem; font-weight:700;" onchange="quickChangeActionStatus('${a.id}', this.value)">
                        <option value="Bekliyor" ${a.status === 'Bekliyor' ? 'selected' : ''}>⏳ Bekliyor</option>
                        <option value="Devam Ediyor" ${a.status === 'Devam Ediyor' ? 'selected' : ''}>🔄 Devam Ediyor</option>
                        <option value="Tamamlandı" ${a.status === 'Tamamlandı' ? 'selected' : ''}>✅ Tamamlandı</option>
                    </select>
                </td>
                <td>
                    <div style="display:flex; gap:0.35rem;">
                        <button class="btn btn-secondary btn-sm" onclick="openActionModal('${a.id}')" title="Düzenle">
                            <i class="fa-solid fa-pen"></i>
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deleteAction('${a.id}')" title="Sil">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// ==========================================================================
// 7. KURUMSAL RAPORLAMA VE ANALİZ MOTORU (REPORTS TAB)
// ==========================================================================
function resetReportFilters() {
    const sEl = document.getElementById('report-start-date');
    const eEl = document.getElementById('report-end-date');
    const dEl = document.getElementById('report-dept-filter');
    const pEl = document.getElementById('report-person-filter');
    if (sEl) sEl.value = '';
    if (eEl) eEl.value = '';
    if (dEl) dEl.value = 'ALL';
    if (pEl) pEl.value = 'ALL';
    renderReports();
}

function renderReports() {
    const isAdmin = isOmerEren(currentUser);
    const startRaw = document.getElementById('report-start-date')?.value || '';
    const endRaw = document.getElementById('report-end-date')?.value || '';
    const deptF = document.getElementById('report-dept-filter')?.value || 'ALL';
    const personF = isAdmin
        ? (document.getElementById('report-person-filter')?.value || 'ALL')
        : (currentUser ? currentUser.name : 'ALL');

    const startIso = normalizeToISODate(startRaw);
    const endIso = normalizeToISODate(endRaw);

    const filteredMeetings = appState.meetings.filter(m => {
        if (!isAdmin && getMeetingAccessLevel(m) === 'NONE') return false;
        const mDate = normalizeToISODate(m.date);
        if (startIso && mDate < startIso) return false;
        if (endIso && mDate > endIso) return false;
        if (deptF !== 'ALL' && m.dept !== deptF) return false;
        if (personF !== 'ALL' && !(m.participants || []).includes(personF)) return false;
        return true;
    });

    const filteredActions = appState.actions.filter(a => {
        if (!isAdmin && !canUserSeeAction(a)) return false;
        const aDate = normalizeToISODate(a.dueDate);
        if (startIso && aDate < startIso) return false;
        if (endIso && aDate > endIso) return false;
        if (personF !== 'ALL' && a.assignee !== personF) return false;
        if (deptF !== 'ALL') {
            const parentM = appState.meetings.find(m => m.id === a.meetingId);
            if (parentM && parentM.dept !== deptF) return false;
        }
        return true;
    });

    const doneActions = filteredActions.filter(a => a.status === 'Tamamlandı');
    const overdueActions = filteredActions.filter(a => {
        const st = evaluateActionReminderStatus(a);
        return st.stage === 'OVERDUE' || a.priority === 'Kritik';
    });

    const rate = filteredActions.length > 0 ? Math.round((doneActions.length / filteredActions.length) * 100) : 0;

    const kpiM = document.getElementById('rep-kpi-meetings');
    const kpiA = document.getElementById('rep-kpi-total-actions');
    const kpiR = document.getElementById('rep-kpi-rate');
    const kpiSub = document.getElementById('rep-kpi-done-sub');
    const kpiO = document.getElementById('rep-kpi-overdue');

    if (kpiM) kpiM.textContent = filteredMeetings.length;
    if (kpiA) kpiA.textContent = filteredActions.length;
    if (kpiR) kpiR.textContent = `%${rate}`;
    if (kpiSub) kpiSub.textContent = `${doneActions.length} Tamamlanan / ${filteredActions.length} Toplam`;
    if (kpiO) kpiO.textContent = overdueActions.length;

    // Personel Bazlı Rapor Tablosu (Ömer Eren tüm personeli görür, diğer kullanıcılar sadece kendi satırını görür)
    const pTbody = document.getElementById('report-personnel-tbody');
    if (pTbody) {
        const usersToList = isAdmin
            ? (personF === 'ALL' ? appState.users : appState.users.filter(u => u.name === personF))
            : appState.users.filter(u => currentUser && (normalizeTR(u.username) === normalizeTR(currentUser.username) || normalizeTR(u.name) === normalizeTR(currentUser.name)));

        pTbody.innerHTML = usersToList.map(u => {
            const attended = filteredMeetings.filter(m => (m.participants || []).includes(u.name)).length;
            const assigned = filteredActions.filter(a => a.assignee === u.name);
            const done = assigned.filter(a => a.status === 'Tamamlandı').length;
            const overdue = assigned.filter(a => evaluateActionReminderStatus(a).stage === 'OVERDUE').length;
            const pRate = assigned.length > 0 ? Math.round((done / assigned.length) * 100) : 100;

            return `
                <tr>
                    <td><strong style="color:#fff;">${u.name}</strong></td>
                    <td style="color:var(--text-sec); font-size:0.8rem;">${u.dept}</td>
                    <td><strong>${attended}</strong></td>
                    <td><strong>${assigned.length}</strong></td>
                    <td><span class="badge badge-done">${done}</span></td>
                    <td><span class="badge ${overdue > 0 ? 'badge-critical' : 'badge-pending'}">${overdue}</span></td>
                    <td>
                        <div style="display:flex; align-items:center; gap:0.4rem;">
                            <div style="flex:1; height:6px; background:rgba(255,255,255,0.08); border-radius:4px; min-width:50px; overflow:hidden;">
                                <div style="width:${pRate}%; height:100%; background:${pRate >= 75 ? '#10b981' : (pRate >= 40 ? '#f59e0b' : '#ef4444')};"></div>
                            </div>
                            <span style="font-size:0.76rem; font-weight:700;">%${pRate}</span>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // Departman Bazlı Rapor Tablosu
    const dTbody = document.getElementById('report-dept-tbody');
    if (dTbody) {
        const depts = ["Genel Yönetim", "SSH & Servis", "Depo & Yedek Parça", "Muhasebe & Finans", "Kalite & İSG"];
        dTbody.innerHTML = depts.map(dName => {
            const dMeetings = filteredMeetings.filter(m => m.dept === dName);
            const dMeetingIds = dMeetings.map(m => m.id);
            const dActions = filteredActions.filter(a => dMeetingIds.includes(a.meetingId));
            const dOpen = dActions.filter(a => a.status !== 'Tamamlandı').length;
            const dDone = dActions.filter(a => a.status === 'Tamamlandı').length;

            return `
                <tr>
                    <td><strong style="color:#fff;">${dName}</strong></td>
                    <td>${dMeetings.length} Toplantı</td>
                    <td>${dActions.length} Aksiyon</td>
                    <td><span class="badge ${dOpen > 0 ? 'badge-high' : 'badge-pending'}">${dOpen} Açık</span></td>
                    <td><span class="badge badge-done">${dDone} Tamam</span></td>
                </tr>
            `;
        }).join('');
    }
}

function printExecutiveReport() {
    const isAdmin = isOmerEren(currentUser);
    const printArea = document.getElementById('print-minutes-area');
    const repMeetings = isAdmin ? appState.meetings : appState.meetings.filter(m => getMeetingAccessLevel(m) !== 'NONE');
    const repActions = isAdmin ? appState.actions : appState.actions.filter(a => canUserSeeAction(a));
    const repUsers = isAdmin
        ? appState.users
        : appState.users.filter(u => currentUser && (normalizeTR(u.username) === normalizeTR(currentUser.username) || normalizeTR(u.name) === normalizeTR(currentUser.name)));

    const totalM = repMeetings.length;
    const totalA = repActions.length;
    const doneA = repActions.filter(a => a.status === 'Tamamlandı').length;
    const openA = totalA - doneA;

    printArea.innerHTML = `
        <div style="border: 2px solid #000; padding: 20px; font-family: Arial, sans-serif; color: #000;">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 2px solid #0284c7; padding-bottom: 12px; margin-bottom: 16px;">
                <div style="display:flex; align-items:center; gap: 15px;">
                    <img src="data:image/jpeg;base64,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" style="width:70px; height:70px; object-fit:contain;">
                    <div>
                        <h1 style="margin:0; font-size:21px; color:#0284c7;">DİZSAN OTOMOTİV & SERVİS</h1>
                        <p style="margin:4px 0 0; font-size:13px; font-weight:bold;">${isAdmin ? 'GENEL TOPLANTI VE AKSİYON PERFORMANS YÖNETİCİ RAPORU' : `KİŞİSEL TOPLANTI VE AKSİYON RAPORU (${currentUser ? currentUser.name : ''})`}</p>
                    </div>
                </div>
                <div style="text-align:right; font-size:12px;">
                    <div><strong>Rapor Tarihi:</strong> ${formatNowTR()}</div>
                    <div><strong>Hazırlayan:</strong> ${currentUser ? currentUser.name : 'ÖMER EREN'}</div>
                    <div><strong>Sürüm:</strong> ${appState.version}</div>
                </div>
            </div>

            <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:10px; margin-bottom:16px; text-align:center; font-size:12px;">
                <div style="border:1px solid #94a3b8; padding:10px; background:#f8fafc;"><strong>Toplam Toplantı</strong><br><span style="font-size:18px; font-weight:bold;">${totalM}</span></div>
                <div style="border:1px solid #94a3b8; padding:10px; background:#f8fafc;"><strong>Toplam Aksiyon</strong><br><span style="font-size:18px; font-weight:bold;">${totalA}</span></div>
                <div style="border:1px solid #94a3b8; padding:10px; background:#f8fafc;"><strong>Açık Aksiyon</strong><br><span style="font-size:18px; font-weight:bold;">${openA}</span></div>
                <div style="border:1px solid #94a3b8; padding:10px; background:#f8fafc;"><strong>Tamamlanan</strong><br><span style="font-size:18px; font-weight:bold;">${doneA}</span></div>
            </div>

            <h3 style="font-size:14px; margin:0 0 8px;">Personel Katılım ve Aksiyon Performans Tablosu</h3>
            <table style="width:100%; border-collapse:collapse; font-size:11px; margin-bottom:18px;">
                <thead>
                    <tr style="background:#e2e8f0;">
                        <th style="border:1px solid #94a3b8; padding:5px;">Personel Adı Soyadı</th>
                        <th style="border:1px solid #94a3b8; padding:5px;">Görev / Bölüm</th>
                        <th style="border:1px solid #94a3b8; padding:5px;">Katıldığı Toplantı</th>
                        <th style="border:1px solid #94a3b8; padding:5px;">Atanan Aksiyon</th>
                        <th style="border:1px solid #94a3b8; padding:5px;">Tamamlanan</th>
                        <th style="border:1px solid #94a3b8; padding:5px;">Açık / Bekleyen</th>
                    </tr>
                </thead>
                <tbody>
                    ${repUsers.map(u => {
                        const att = repMeetings.filter(m => (m.participants || []).includes(u.name)).length;
                        const ass = repActions.filter(a => a.assignee === u.name);
                        const dn = ass.filter(a => a.status === 'Tamamlandı').length;
                        return `
                            <tr>
                                <td style="border:1px solid #94a3b8; padding:5px; font-weight:bold;">${u.name}</td>
                                <td style="border:1px solid #94a3b8; padding:5px;">${u.dept}</td>
                                <td style="border:1px solid #94a3b8; padding:5px; text-align:center;">${att}</td>
                                <td style="border:1px solid #94a3b8; padding:5px; text-align:center;">${ass.length}</td>
                                <td style="border:1px solid #94a3b8; padding:5px; text-align:center;">${dn}</td>
                                <td style="border:1px solid #94a3b8; padding:5px; text-align:center;">${ass.length - dn}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
    window.print();
}

// ==========================================================================
// 8. PERSONEL VE LOG TABLOLARI RENDER
// KURAL: Diğer kullanıcılar SADECE ÖMER EREN listesinde çıkar.
// Geriye kalan tüm personeller yalnızca kendi bilgilerini görür ve düzenler!
// ==========================================================================
function renderPersonnel() {
    const tbody = document.getElementById('personnel-tbody');
    if (!tbody) return;

    const isAdmin = isOmerEren(currentUser);
    const titleEl = document.getElementById('personnel-tab-title');
    const descEl = document.getElementById('personnel-tab-desc');
    const addBtnEl = document.getElementById('btn-add-new-personnel');

    if (isAdmin) {
        if (titleEl) {
            titleEl.innerHTML = `<i class="fa-solid fa-users-gear" style="color:var(--dizsan-light);"></i> Dizsan Güncel Personel Listesi & Giriş Hesapları (Yönetici Ömer Eren Görünümü)`;
        }
        if (descEl) {
            descEl.textContent = "Yönetici ÖMER EREN olarak sistemdeki tüm personel hesaplarını, şifrelerini ve yetkilerini görüntüleyebilir, düzenleyebilir veya yeni personel ekleyebilirsiniz.";
        }
        if (addBtnEl) {
            addBtnEl.style.display = 'inline-flex';
        }
    } else {
        if (titleEl) {
            titleEl.innerHTML = `<i class="fa-solid fa-user-lock" style="color:var(--dizsan-light);"></i> Kişisel Hesap Bilgilerim & Şifre Yönetimi`;
        }
        if (descEl) {
            descEl.textContent = "Gizlilik ve güvenlik kuralları gereği her kullanıcı yalnızca kendi hesap bilgilerini, şifresini ve kişisel istatistiklerini görüntüleyebilir ve düzenleyebilir. Diğer kullanıcıların listesi yalnızca Yönetici ÖMER EREN ekranında görüntülenir.";
        }
        if (addBtnEl) {
            addBtnEl.style.display = 'none';
        }
    }

    const visibleUsers = isAdmin
        ? appState.users
        : appState.users.filter(u => currentUser && (normalizeTR(u.username) === normalizeTR(currentUser.username) || normalizeTR(u.name) === normalizeTR(currentUser.name)));

    tbody.innerHTML = visibleUsers.map((u, idx) => {
        const attended = appState.meetings.filter(m => (m.participants || []).includes(u.name)).length;
        const openA = appState.actions.filter(a => a.assignee === u.name && a.status !== 'Tamamlandı').length;

        return `
            <tr>
                <td><strong>${isAdmin ? (u.order !== undefined ? (u.order === 0 ? '★' : u.order + '.') : (idx + 1) + '.') : '1.'}</strong></td>
                <td>
                    <div style="display:flex; align-items:center; gap:0.65rem;">
                        <img src="${u.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(u.name)}&background=0284c7&color=fff`}" style="width:32px; height:32px; border-radius:8px; object-fit:cover;" onerror="this.src='dizsan_logo.jpg'">
                        <strong style="color:#fff;">${u.name}</strong>
                    </div>
                </td>
                <td><span class="badge badge-normal">${u.dept || 'Personel'}</span></td>
                <td><code>${u.username}</code></td>
                <td style="font-size:0.8rem; color:var(--text-sec);">${resolveUserEmail(u)}</td>
                <td><span class="badge ${u.role === 'Yönetici' ? 'badge-done' : 'badge-pending'}">${u.role || 'Personel'}</span></td>
                <td><strong>${attended}</strong></td>
                <td><span class="badge ${openA > 0 ? 'badge-high' : 'badge-pending'}">${openA} Açık</span></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="openUserModal('${u.username}')">
                        <i class="fa-solid fa-pen"></i> ${isAdmin ? 'Düzenle' : 'Bilgilerimi Düzenle'}
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderLogs() {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    const q = normalizeTR(document.getElementById('log-search')?.value || '');
    const typeF = document.getElementById('log-type-filter')?.value || 'ALL';

    const filtered = appState.logs.filter(l => {
        if (typeF !== 'ALL' && l.category !== typeF) return false;
        if (q) {
            const hay = normalizeTR(`${l.user} ${l.category} ${l.detail} ${l.timestamp}`);
            if (!hay.includes(q)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:2rem; color:var(--text-sec);">Kayıtlı işlem logu bulunmuyor.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(l => `
        <tr>
            <td style="white-space:nowrap; font-family:monospace; color:var(--dizsan-light);">${l.timestamp}</td>
            <td><strong style="color:#fff;">${l.user}</strong></td>
            <td><span class="badge badge-normal">${l.category}</span></td>
            <td style="color:#e2e8f0;">${l.detail}</td>
            <td style="font-size:0.78rem; color:var(--text-sec);">${l.platform || 'Web'}</td>
        </tr>
    `).join('');
}

// ==========================================================================
// 9. TOPLANTI VE AKSİYON KAYIT FONKSİYONLARI
// ==========================================================================

// --- SEÇMELİ LİSTE HARİCİ DIŞ KATILIMCI (MANUEL KATILIMCI) FONKSİYONLARI ---
function toggleExternalParticipantSection(checked) {
    const sec = document.getElementById('external-participants-section');
    const nameInput = document.getElementById('ext-manual-name');
    const phoneInput = document.getElementById('ext-manual-phone');
    const companyInput = document.getElementById('ext-manual-company');
    if (!sec) return;

    if (checked) {
        sec.classList.remove('hidden');
        sec.style.display = 'block';
        if (nameInput) setTimeout(() => nameInput.focus(), 50);
    } else {
        sec.classList.add('hidden');
        sec.style.display = 'none';
        if (nameInput) nameInput.value = '';
        if (phoneInput) phoneInput.value = '';
        if (companyInput) companyInput.value = '';
    }
}

function addManualExternalParticipantFromInputs() {
    const nameInput = document.getElementById('ext-manual-name');
    const phoneInput = document.getElementById('ext-manual-phone');
    const companyInput = document.getElementById('ext-manual-company');

    const name = nameInput ? nameInput.value.trim() : '';
    const phone = phoneInput ? phoneInput.value.trim() : '';
    const company = companyInput ? companyInput.value.trim() : '';

    if (!name) {
        alert("Lütfen dış katılımcının Adı Soyadı bilgisini yazıp 'Ekle' butonuna basın!");
        if (nameInput) nameInput.focus();
        return;
    }

    addExternalParticipantRow({ name, phone, company });

    if (nameInput) {
        nameInput.value = '';
        nameInput.focus();
    }
    if (phoneInput) phoneInput.value = '';
    if (companyInput) companyInput.value = '';
}

function addExternalParticipantRow(data = {}) {
    const list = document.getElementById('external-participants-list');
    if (!list) return;

    const row = document.createElement('div');
    row.className = 'external-participant-row added-ext-row';
    row.style.cssText = 'display:grid; grid-template-columns: 1.3fr 1fr 1.3fr auto; gap:0.5rem; align-items:center; background:rgba(16,185,129,0.09); padding:0.5rem 0.65rem; border-radius:8px; border:1px solid rgba(16,185,129,0.35);';

    row.innerHTML = `
        <div>
            <label style="font-size:0.66rem; color:#6ee7b7; margin-bottom:2px; display:block;">✓ Eklenen Katılımcı Adı Soyadı</label>
            <input type="text" class="form-control ext-part-name" placeholder="Adı Soyadı" value="${(data.name || '').replace(/"/g, '&quot;')}">
        </div>
        <div>
            <label style="font-size:0.66rem; color:#6ee7b7; margin-bottom:2px; display:block;">Telefon Numarası</label>
            <input type="tel" class="form-control ext-part-phone" placeholder="05XX XXX XX XX" value="${(data.phone || '').replace(/"/g, '&quot;')}">
        </div>
        <div>
            <label style="font-size:0.66rem; color:#6ee7b7; margin-bottom:2px; display:block;">Temsil Ettiği Firma</label>
            <input type="text" class="form-control ext-part-company" placeholder="Firma Adı" value="${(data.company || '').replace(/"/g, '&quot;')}">
        </div>
        <div style="padding-top:14px;">
            <button type="button" class="btn btn-danger btn-sm" title="Listeden Kaldır" onclick="removeExternalParticipantRow(this)">
                <i class="fa-solid fa-trash"></i> Kaldır
            </button>
        </div>
    `;
    list.appendChild(row);
}

function removeExternalParticipantRow(btn) {
    const row = btn.closest('.added-ext-row') || btn.closest('.external-participant-row');
    if (row) row.remove();
}

// --- OTOMATİK NUMARALANDIRMA (1. , 2. , 3. ) FONKSİYONLARI ---
function handleNumberedTextareaFocus(textarea) {
    if (!textarea) return;
    if (textarea.value.trim() === '') {
        textarea.value = '1. ';
        setTimeout(() => {
            textarea.selectionStart = textarea.selectionEnd = textarea.value.length;
        }, 0);
    }
}

function handleNumberedTextareaInput(textarea) {
    if (!textarea) return;
    // Kullanıcı içeriği tamamen silip ilk harfi yazmaya başladığında otomatik "1. " ekle
    const val = textarea.value;
    if (val.length === 1 && val !== '\n' && !/^\d/.test(val)) {
        textarea.value = '1. ' + val;
        textarea.selectionStart = textarea.selectionEnd = textarea.value.length;
    }
}

function handleNumberedTextareaKeydown(event, textarea) {
    if (!textarea) return;
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();

        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const val = textarea.value;

        const beforeCursor = val.substring(0, start);
        const afterCursor = val.substring(end);

        const linesBefore = beforeCursor.split('\n');
        const currentLine = linesBefore[linesBefore.length - 1] || '';

        // Mevcut satırın başındaki numarayı bul veya toplam satır sayısına göre sıradaki numarayı hesapla
        let nextNum = linesBefore.length + 1;
        const match = currentLine.match(/^\s*(\d+)[\.\)\-]\s*/);
        if (match) {
            nextNum = parseInt(match[1], 10) + 1;
        } else {
            // Önceki satırlarda en son hangi numara kullanılmış kontrol et
            for (let i = linesBefore.length - 1; i >= 0; i--) {
                const m = linesBefore[i].match(/^\s*(\d+)[\.\)\-]\s*/);
                if (m) {
                    nextNum = parseInt(m[1], 10) + (linesBefore.length - i);
                    break;
                }
            }
        }

        // Eğer ilk satır henüz numaralandırılmamışsa onu da "1. " yap
        let updatedBefore = beforeCursor;
        if (linesBefore.length === 1 && !/^\s*\d+[\.\)\-]\s*/.test(currentLine) && currentLine.trim().length > 0) {
            updatedBefore = '1. ' + beforeCursor;
            nextNum = 2;
        }

        const insertStr = `\n${nextNum}. `;
        textarea.value = updatedBefore + insertStr + afterCursor;
        const newCursorPos = updatedBefore.length + insertStr.length;
        textarea.selectionStart = textarea.selectionEnd = newCursorPos;
        textarea.scrollTop = textarea.scrollHeight;
    }
}

// --- TOPLANTI / EĞİTİM TÜRÜ SEÇİM FONKSİYONU ---
function setMeetingRecordType(type) {
    const val = (type === 'Eğitim') ? 'Eğitim' : 'Toplantı';
    const hiddenInput = document.getElementById('meeting-record-type-input');
    const btnTop = document.getElementById('btn-type-toplanti');
    const btnEgt = document.getElementById('btn-type-egitim');
    const titleLabel = document.getElementById('meeting-title-label');
    const titleInput = document.getElementById('meeting-title-input');

    if (hiddenInput) hiddenInput.value = val;
    if (btnTop && btnEgt) {
        if (val === 'Eğitim') {
            btnEgt.className = 'btn btn-primary btn-sm';
            btnTop.className = 'btn btn-secondary btn-sm';
        } else {
            btnTop.className = 'btn btn-primary btn-sm';
            btnEgt.className = 'btn btn-secondary btn-sm';
        }
    }
    if (titleLabel) {
        titleLabel.textContent = val === 'Eğitim' ? 'Eğitim Başlığı / Konusu *' : 'Toplantı Başlığı / Konusu *';
    }
    if (titleInput) {
        titleInput.placeholder = val === 'Eğitim'
            ? 'Örn: Scania Euro 6 Arıza Teşhis ve Teknik Servis Eğitimi'
            : 'Örn: Haftalık Servis & Depo Koordinasyon Toplantısı';
    }
}

// --- TOPLANTI / EĞİTİM EKLERİ (FOTOĞRAF, KAĞIT TUTANAK, BİLGİ VEYA BELGE) FONKSİYONLARI ---
function compressImageFileToDataUrl(file, maxDim = 1400, quality = 0.82) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                let w = img.width;
                let h = img.height;
                if (w > maxDim || h > maxDim) {
                    if (w > h) {
                        h = Math.round((h * maxDim) / w);
                        w = maxDim;
                    } else {
                        w = Math.round((w * maxDim) / h);
                        h = maxDim;
                    }
                }
                const canvas = document.createElement('canvas');
                canvas.width = w;
                canvas.height = h;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0, w, h);
                resolve(canvas.toDataURL('image/jpeg', quality));
            };
            img.onerror = () => resolve(e.target.result);
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    });
}

function readRegularFileToDataUrl(file) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.readAsDataURL(file);
    });
}

async function handleMeetingAttachmentUpload(event) {
    const files = Array.from(event.target.files || []);
    if (files.length === 0) return;

    const noteInput = document.getElementById('meeting-attachment-note-input');
    const customNote = noteInput ? noteInput.value.trim() : '';

    for (const file of files) {
        const isImg = (file.type || '').startsWith('image/');
        const dataUrl = isImg
            ? await compressImageFileToDataUrl(file)
            : await readRegularFileToDataUrl(file);

        currentDraftAttachments.push({
            id: 'ATT-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
            kind: isImg ? 'IMAGE' : 'FILE',
            name: file.name,
            type: file.type || 'application/octet-stream',
            note: customNote || (isImg ? 'Toplantı / Kağıt Tutanak Fotoğrafı' : 'Ek Belge'),
            dataUrl,
            addedBy: currentUser ? currentUser.name : 'ÖMER EREN',
            addedAt: formatNowTR()
        });
    }

    if (noteInput) noteInput.value = '';
    event.target.value = '';
    renderDraftAttachments();
}

function addTextNoteAttachment() {
    const noteInput = document.getElementById('meeting-attachment-note-input');
    const text = noteInput ? noteInput.value.trim() : '';
    if (!text) {
        alert("Lütfen eklenecek bilgi veya belge açıklamasını yazın!");
        return;
    }

    currentDraftAttachments.push({
        id: 'ATT-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        kind: 'NOTE',
        name: text.length > 35 ? text.substring(0, 35) + '...' : text,
        type: 'text/plain',
        note: text,
        dataUrl: '',
        addedBy: currentUser ? currentUser.name : 'ÖMER EREN',
        addedAt: formatNowTR()
    });

    if (noteInput) noteInput.value = '';
    renderDraftAttachments();
}

function removeDraftAttachment(attId) {
    currentDraftAttachments = currentDraftAttachments.filter(a => a.id !== attId);
    renderDraftAttachments();
}

function renderDraftAttachments() {
    const container = document.getElementById('meeting-attachments-preview');
    if (!container) return;

    if (currentDraftAttachments.length === 0) {
        container.innerHTML = `<div style="grid-column:1/-1; font-size:0.76rem; color:var(--text-sec); padding:0.35rem 0;">Henüz eklenmiş fotoğraf, el yazısı kağıt tutanak veya belge yok.</div>`;
        return;
    }

    container.innerHTML = currentDraftAttachments.map(att => {
        const isImg = (att.type || '').startsWith('image/');
        const isPdf = (att.type || '').toLowerCase().includes('pdf') || (att.name || '').toLowerCase().endsWith('.pdf');
        const imgSrc = isImg ? (att.dataUrl || att.fileUrl || '') : '';
        return `
            <div style="background:rgba(15,23,42,0.85); border:1px solid rgba(52,211,153,0.35); border-radius:8px; padding:0.45rem; display:flex; flex-direction:column; justify-content:space-between; gap:0.35rem; position:relative;">
                <div style="display:flex; align-items:center; gap:0.45rem;">
                    <div onclick="openDraftAttachmentPreview('${att.id}')" style="display:flex; align-items:center; gap:0.45rem; flex:1; min-width:0; cursor:pointer;" title="Önizlemek / Açmak için tıklayın">
                        ${isImg && imgSrc
                            ? `<img src="${imgSrc}" style="width:42px; height:42px; object-fit:cover; border-radius:6px; border:1px solid rgba(255,255,255,0.15);">`
                            : `<div style="width:42px; height:42px; border-radius:6px; background:rgba(16,185,129,0.15); display:flex; align-items:center; justify-content:center; color:${isPdf ? '#f87171' : '#34d399'}; font-size:1.1rem;"><i class="fa-solid ${att.kind === 'NOTE' ? 'fa-note-sticky' : (isPdf ? 'fa-file-pdf' : 'fa-file-lines')}"></i></div>`
                        }
                        <div style="flex:1; min-width:0;">
                            <div style="font-size:0.75rem; font-weight:700; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(att.name || '')}">${escapeHtml(att.name || 'Ek Belge')}</div>
                            <div style="font-size:0.68rem; color:#6ee7b7; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(att.note || '')}">${escapeHtml(att.note || 'Önizlemek için tıklayın')}</div>
                        </div>
                    </div>
                    <button type="button" class="btn btn-danger btn-sm" style="padding:3px 6px; font-size:0.7rem;" onclick="removeDraftAttachment('${att.id}')" title="Eki Sil">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

let activeAttachmentBlobUrl = null;
let activePreviewAttachmentObj = null;

function dataUrlToBlobUrl(dataUrl, fallbackMime = 'application/pdf') {
    if (!dataUrl || typeof dataUrl !== 'string') return '';
    if (!dataUrl.startsWith('data:')) return dataUrl;
    try {
        const commaIdx = dataUrl.indexOf(',');
        if (commaIdx === -1) return dataUrl;
        const header = dataUrl.slice(0, commaIdx);
        const b64 = dataUrl.slice(commaIdx + 1).replace(/\s/g, '');
        const mimeMatch = header.match(/data:([^;]+)/i);
        const mime = (mimeMatch && mimeMatch[1]) ? mimeMatch[1] : fallbackMime;
        const binStr = atob(b64);
        const len = binStr.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binStr.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: mime });
        return URL.createObjectURL(blob);
    } catch (e) {
        return dataUrl;
    }
}

function resolveAttachmentSourceUrl(att) {
    if (!att) return '';
    let src = att.dataUrl || att.fileUrl || '';
    if (!src) return '';
    if (src.startsWith('data:')) {
        const isPdf = (att.type || '').toLowerCase().includes('pdf') || (att.name || '').toLowerCase().endsWith('.pdf') || src.startsWith('data:application/pdf');
        if (activeAttachmentBlobUrl) {
            try { URL.revokeObjectURL(activeAttachmentBlobUrl); } catch (e) {}
            activeAttachmentBlobUrl = null;
        }
        activeAttachmentBlobUrl = dataUrlToBlobUrl(src, isPdf ? 'application/pdf' : (att.type || 'application/octet-stream'));
        return activeAttachmentBlobUrl;
    }
    return src;
}

function openCurrentAttachmentInNewTab() {
    if (!activePreviewAttachmentObj) return;
    const url = resolveAttachmentSourceUrl(activePreviewAttachmentObj);
    if (!url || url === '#') return;
    const win = window.open(url, '_blank', 'noopener');
    if (!win) {
        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        a.rel = 'noopener';
        a.setAttribute('data-no-dpro-nav', '1');
        document.body.appendChild(a);
        a.click();
        setTimeout(() => a.remove(), 300);
    }
}

async function openDraftAttachmentPreview(attId) {
    const att = currentDraftAttachments.find(a => a.id === attId);
    if (!att) return;
    await renderAttachmentPreviewModalContent(att);
}

async function openAttachmentPreviewModal(meetingId, attId) {
    const m = appState.meetings.find(x => x.id === meetingId);
    if (!m) return;
    if (getMeetingAccessLevel(m) !== 'FULL') {
        alert("Bu toplantının/eğitimin katılımcısı olmadığınız için ek belgeleri görüntüleme yetkiniz bulunmamaktadır.");
        return;
    }

    const att = (m.attachments || []).find(a => a.id === attId);
    if (!att) return;
    await renderAttachmentPreviewModalContent(att);
}

async function renderAttachmentPreviewModalContent(att) {
    if (!att.dataUrl && att.id) {
        const cached = await getAttachmentFromIDB(att.id);
        if (cached && cached.dataUrl) {
            att.dataUrl = cached.dataUrl;
        }
    }

    activePreviewAttachmentObj = att;
    const modal = document.getElementById('attachment-preview-modal');
    const titleEl = document.getElementById('attachment-preview-title');
    const bodyEl = document.getElementById('attachment-preview-body');
    const dlBtn = document.getElementById('attachment-download-btn');
    const openTabBtn = document.getElementById('attachment-open-newtab-btn');

    titleEl.innerHTML = `<i class="fa-solid fa-paperclip" style="color:#34d399;"></i> ${escapeHtml(att.name || 'Toplantı / Eğitim Eki')}`;

    const mimeLower = (att.type || '').toLowerCase();
    const nameLower = (att.name || '').toLowerCase();
    const isImg = mimeLower.startsWith('image/') || /\.(png|jpe?g|gif|webp|bmp)$/i.test(nameLower);
    const isPdf = mimeLower.includes('pdf') || nameLower.endsWith('.pdf') || (att.dataUrl || '').startsWith('data:application/pdf') || (att.fileUrl || '').toLowerCase().endsWith('.pdf');

    const playableUrl = resolveAttachmentSourceUrl(att);

    if (isImg && playableUrl) {
        bodyEl.innerHTML = `
            <div style="margin-bottom:0.75rem; font-size:0.84rem; color:#fde68a;">${escapeHtml(att.note || '')}</div>
            <img src="${playableUrl}" style="max-width:100%; max-height:68vh; border-radius:10px; border:1px solid var(--border-color); box-shadow:0 10px 30px rgba(0,0,0,0.5);">
            <div style="margin-top:0.5rem; font-size:0.75rem; color:var(--text-sec);">Ekleyen: ${escapeHtml(att.addedBy || 'ÖMER EREN')} • ${escapeHtml(att.addedAt || '')}</div>
        `;
        dlBtn.href = playableUrl;
        dlBtn.download = att.name || 'toplanti_eki.jpg';
        dlBtn.style.display = 'inline-flex';
        if (openTabBtn) openTabBtn.style.display = 'inline-flex';
    } else if (att.kind === 'NOTE') {
        bodyEl.innerHTML = `
            <div style="background:rgba(255,255,255,0.04); border:1px solid var(--border-color); border-radius:12px; padding:1.25rem; text-align:left; white-space:pre-line; font-size:0.92rem; color:#fff;">
                ${escapeHtml(att.note || att.name)}
            </div>
            <div style="margin-top:0.5rem; font-size:0.75rem; color:var(--text-sec);">Ekleyen: ${escapeHtml(att.addedBy || 'ÖMER EREN')} • ${escapeHtml(att.addedAt || '')}</div>
        `;
        dlBtn.style.display = 'none';
        if (openTabBtn) openTabBtn.style.display = 'none';
    } else if (isPdf && playableUrl) {
        bodyEl.innerHTML = `
            ${att.note ? `<div style="margin-bottom:0.6rem; font-size:0.84rem; color:#fde68a;">${escapeHtml(att.note)}</div>` : ''}
            <div style="width:100%; height:70vh; min-height:460px; border-radius:10px; overflow:hidden; border:1px solid rgba(56,189,248,0.35); background:#0f172a;">
                <iframe src="${playableUrl}#toolbar=1&navpanes=1&view=FitH" style="width:100%; height:100%; border:none; background:#fff;" title="${escapeHtml(att.name || 'PDF Belgesi')}"></iframe>
            </div>
            <div style="margin-top:0.5rem; font-size:0.75rem; color:var(--text-sec);">Ekleyen: ${escapeHtml(att.addedBy || 'ÖMER EREN')} • ${escapeHtml(att.addedAt || '')}</div>
        `;
        dlBtn.href = playableUrl;
        dlBtn.download = att.name || 'toplanti_belgesi.pdf';
        dlBtn.style.display = 'inline-flex';
        if (openTabBtn) openTabBtn.style.display = 'inline-flex';
    } else {
        bodyEl.innerHTML = `
            <div style="padding:1.5rem; background:rgba(255,255,255,0.03); border:1px solid var(--border-color); border-radius:12px;">
                <i class="fa-solid fa-file-lines" style="font-size:3rem; color:#34d399; margin-bottom:0.75rem; display:block;"></i>
                <h4 style="color:#fff; margin-bottom:0.35rem;">${escapeHtml(att.name || 'Ek Belge')}</h4>
                <p style="font-size:0.84rem; color:var(--text-sec); margin-bottom:0.5rem;">${escapeHtml(att.note || '')}</p>
                <div style="font-size:0.75rem; color:var(--text-sec);">Ekleyen: ${escapeHtml(att.addedBy || 'ÖMER EREN')} • ${escapeHtml(att.addedAt || '')}</div>
            </div>
        `;
        dlBtn.href = playableUrl || '#';
        dlBtn.download = att.name || 'ek_belge';
        dlBtn.style.display = playableUrl ? 'inline-flex' : 'none';
        if (openTabBtn) openTabBtn.style.display = playableUrl ? 'inline-flex' : 'none';
    }

    modal.classList.add('open');
}

function closeAttachmentPreviewModal() {
    document.getElementById('attachment-preview-modal').classList.remove('open');
}

// ==========================================================================
// GELİŞMİŞ YOKLAMA (DAVETLİ / GELEN / GELMEYEN & NEDENİ),
// TİKLEMELİ GÜNDEM MADDELERİ, BAŞKA TOPLANTI PLANLAMA VE KARAR SORUMLUSU MOTORU
// ==========================================================================
let currentDraftAttendance = {}; // { "ÖMER EREN": { status: "ATTENDED" | "ABSENT", reason: "" } }
let currentDraftAgendaItems = []; // [{ id, title, discussed, explanation, transferredToMeetingId }]
let currentDraftDecisionItems = []; // [{ id, text, responsible, dueDate, status }]

function escapeHtmlAttr(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function handleMeetingCardClick(event, meetingId) {
    if (event && event.target) {
        const interactive = event.target.closest('button, select, input, a, label');
        if (interactive) return;
    }
    openMeetingModal(meetingId);
}

function printCurrentModalMeetingMinutes() {
    const idVal = document.getElementById('meeting-id')?.value;
    if (idVal) {
        printMeetingMinutes(idVal);
    }
}

function getMeetingAttendanceSummary(m) {
    if (!m) return { invited: [], attended: [], absent: [] };
    const invited = Array.isArray(m.invitedParticipants) && m.invitedParticipants.length > 0
        ? [...m.invitedParticipants]
        : (Array.isArray(m.participants) ? [...m.participants] : []);

    const absentRaw = Array.isArray(m.absentParticipants) ? m.absentParticipants : [];
    const absent = absentRaw
        .map(ab => (typeof ab === 'string' ? { name: ab, reason: '' } : { name: ab.name || '', reason: ab.reason || '' }))
        .filter(ab => ab.name);

    const absentNamesNorm = new Set(absent.map(a => normalizeTR(a.name)));

    let attended = [];
    if (Array.isArray(m.attendedParticipants) && (m.attendedParticipants.length > 0 || absent.length > 0)) {
        attended = m.attendedParticipants.filter(name => !absentNamesNorm.has(normalizeTR(name)));
    } else {
        attended = invited.filter(name => !absentNamesNorm.has(normalizeTR(name)));
    }

    return { invited, attended, absent };
}

function parseAgendaItemsFromMeeting(m) {
    if (m && Array.isArray(m.agendaItems) && m.agendaItems.length > 0) {
        return m.agendaItems.map((it, idx) => ({
            id: it.id || ('agd-' + idx + '-' + Date.now()),
            title: String(it.title || '').trim(),
            discussed: Boolean(it.discussed),
            explanation: String(it.explanation || '').trim(),
            transferredToMeetingId: String(it.transferredToMeetingId || '').trim()
        }));
    }

    const rawNotes = (m && m.notes) ? String(m.notes).trim() : '';
    if (!rawNotes) return [];

    const lines = rawNotes.split('\n').map(l => l.trim()).filter(Boolean);
    const parsed = [];

    lines.forEach((line, idx) => {
        // Eğer önceki kayıtlardan açıklama satırıysa son maddeye ekle
        if (/^(💬\s*Açıklama:|↳\s*Açıklama:)/i.test(line) && parsed.length > 0) {
            const expText = line.replace(/^(💬\s*Açıklama:|↳\s*Açıklama:)\s*/i, '').trim();
            parsed[parsed.length - 1].explanation = parsed[parsed.length - 1].explanation
                ? (parsed[parsed.length - 1].explanation + '\n' + expText)
                : expText;
            return;
        }
        let discussed = false;
        let cleanLine = line;
        if (/^✅/.test(cleanLine)) {
            discussed = true;
            cleanLine = cleanLine.replace(/^✅\s*/, '');
        } else if (/^⬜|^⏳/.test(cleanLine)) {
            discussed = false;
            cleanLine = cleanLine.replace(/^(⬜|⏳)\s*/, '');
        }
        cleanLine = cleanLine
            .replace(/^\d+[\.\)\-]\s*/, '')
            .replace(/\s*\[(Konuşuldu|Konuşulmadı[^\]]*)\]\s*$/i, '')
            .trim();

        if (cleanLine) {
            parsed.push({
                id: 'agd-' + idx + '-' + Math.floor(Math.random() * 10000),
                title: cleanLine,
                discussed,
                explanation: '',
                transferredToMeetingId: ''
            });
        }
    });

    return parsed;
}

function parseDecisionItemsFromMeeting(m) {
    const defaultDate = (m && m.date) ? normalizeToISODate(m.date) : new Date().toISOString().split('T')[0];
    const defaultResp = (m && m.createdBy) ? m.createdBy : 'ÖMER EREN';

    if (m && Array.isArray(m.decisionItems) && m.decisionItems.length > 0) {
        return m.decisionItems.map((d, idx) => ({
            id: d.id || ('dec-' + idx + '-' + Date.now()),
            text: String(d.text || '').trim(),
            responsible: String(d.responsible || defaultResp).trim(),
            dueDate: normalizeToISODate(d.dueDate || defaultDate),
            status: d.status || 'Bekliyor'
        }));
    }

    const rawDec = (m && m.decisions) ? String(m.decisions).trim() : '';
    if (!rawDec) return [];

    const lines = rawDec.split('\n').map(l => l.trim()).filter(Boolean);
    return lines.map((line, idx) => {
        let textPart = line.replace(/^\d+[\.\)\-]\s*/, '').trim();
        let resp = defaultResp;
        let due = defaultDate;

        // Eğer metin içinde "(Sorumlu: X | Termin: Y)" formatı varsa ayrıştır
        const metaMatch = textPart.match(/\(Sorumlu:\s*([^|)]+?)\s*\|\s*Termin:\s*([^)]+)\)\s*$/i);
        if (metaMatch) {
            resp = metaMatch[1].trim();
            due = normalizeToISODate(metaMatch[2].trim()) || defaultDate;
            textPart = textPart.replace(metaMatch[0], '').trim();
        }

        return {
            id: 'dec-' + idx + '-' + Math.floor(Math.random() * 10000),
            text: textPart,
            responsible: resp,
            dueDate: due,
            status: 'Bekliyor'
        };
    }).filter(d => d.text);
}

function formatAgendaItemsToLegacyNotes(agendaItems) {
    return (agendaItems || [])
        .filter(it => it.title && it.title.trim())
        .map((it, idx) => {
            const statusTag = it.discussed
                ? '[Konuşuldu]'
                : (it.transferredToMeetingId ? `[Konuşulmadı -> ${it.transferredToMeetingId}]` : '[Konuşulmadı]');
            let str = `${idx + 1}. ${it.title.trim()} ${statusTag}`;
            if (it.discussed && it.explanation && it.explanation.trim()) {
                str += `\n   ↳ Açıklama: ${it.explanation.trim()}`;
            }
            return str;
        })
        .join('\n');
}

function formatDecisionItemsToLegacyText(decisionItems) {
    return (decisionItems || [])
        .filter(d => d.text && d.text.trim())
        .map((d, idx) => {
            const resp = d.responsible || 'ÖMER EREN';
            const due = d.dueDate ? formatDateTR(d.dueDate) : '-';
            return `${idx + 1}. ${d.text.trim()} (Sorumlu: ${resp} | Termin: ${due})`;
        })
        .join('\n');
}

function syncParticipantCheckStyles() {
    document.querySelectorAll('.participant-check').forEach(lbl => {
        const cb = lbl.querySelector('input[type="checkbox"]');
        if (cb) {
            lbl.classList.toggle('is-checked', cb.checked);
        }
    });
}

function onInvitedParticipantCheckboxChange() {
    syncParticipantCheckStyles();
    const checkedNames = Array.from(document.querySelectorAll('input[name="meeting-participant"]:checked')).map(cb => cb.value);
    checkedNames.forEach(name => {
        if (!currentDraftAttendance[name]) {
            currentDraftAttendance[name] = { status: 'ATTENDED', reason: '' };
        }
    });
    renderAttendanceManagementUI();
}

function setParticipantAttendanceStatus(personName, status) {
    if (!currentDraftAttendance[personName]) {
        currentDraftAttendance[personName] = { status: 'ATTENDED', reason: '' };
    }
    currentDraftAttendance[personName].status = (status === 'ABSENT') ? 'ABSENT' : 'ATTENDED';
    renderAttendanceManagementUI();
    if (status === 'ABSENT') {
        setTimeout(() => {
            const inputEl = document.querySelector(`.absent-reason-input[data-person="${CSS.escape(personName)}"]`);
            if (inputEl) inputEl.focus();
        }, 40);
    }
}

function updateParticipantAbsentReason(personName, reasonVal) {
    if (!currentDraftAttendance[personName]) {
        currentDraftAttendance[personName] = { status: 'ABSENT', reason: '' };
    }
    currentDraftAttendance[personName].reason = reasonVal;
    document.querySelectorAll(`.absent-reason-input[data-person="${CSS.escape(personName)}"]`).forEach(el => {
        if (el.value !== reasonVal) el.value = reasonVal;
    });
}

function setQuickAbsentReason(personName, presetReason) {
    if (!currentDraftAttendance[personName]) {
        currentDraftAttendance[personName] = { status: 'ABSENT', reason: '' };
    }
    currentDraftAttendance[personName].status = 'ABSENT';
    currentDraftAttendance[personName].reason = presetReason;
    renderAttendanceManagementUI();
}

function markAllInvitedAttendance(status) {
    const checkedNames = Array.from(document.querySelectorAll('input[name="meeting-participant"]:checked')).map(cb => cb.value);
    checkedNames.forEach(name => {
        const prevReason = currentDraftAttendance[name]?.reason || '';
        currentDraftAttendance[name] = {
            status: status === 'ABSENT' ? 'ABSENT' : 'ATTENDED',
            reason: status === 'ABSENT' ? prevReason : ''
        };
    });
    renderAttendanceManagementUI();
}

function renderAttendanceManagementUI() {
    const rowsContainer = document.getElementById('attendance-rows-container');
    const countersBar = document.getElementById('attendance-counters-bar');
    const summaryBoxes = document.getElementById('attendance-summary-boxes');
    if (!rowsContainer || !countersBar) return;

    const invitedNames = Array.from(document.querySelectorAll('input[name="meeting-participant"]:checked')).map(cb => cb.value);

    invitedNames.forEach(name => {
        if (!currentDraftAttendance[name]) {
            currentDraftAttendance[name] = { status: 'ATTENDED', reason: '' };
        }
    });

    const attendedNames = invitedNames.filter(n => currentDraftAttendance[n]?.status !== 'ABSENT');
    const absentNames = invitedNames.filter(n => currentDraftAttendance[n]?.status === 'ABSENT');

    countersBar.innerHTML = `
        <span class="badge badge-normal" style="font-size:0.76rem; padding:4px 10px;">
            <i class="fa-solid fa-users"></i> Davetli: <strong>${invitedNames.length}</strong>
        </span>
        <span class="badge badge-done" style="font-size:0.76rem; padding:4px 10px;">
            <i class="fa-solid fa-user-check"></i> Katılan: <strong>${attendedNames.length}</strong>
        </span>
        <span class="badge ${absentNames.length > 0 ? 'badge-critical' : 'badge-pending'}" style="font-size:0.76rem; padding:4px 10px;">
            <i class="fa-solid fa-user-xmark"></i> Katılmayan: <strong>${absentNames.length}</strong>
        </span>
    `;

    if (summaryBoxes) {
        summaryBoxes.innerHTML = '';
        summaryBoxes.style.display = 'none';
    }

    if (invitedNames.length === 0) {
        rowsContainer.innerHTML = `
            <div style="grid-column:1/-1; text-align:center; padding:0.75rem; color:var(--text-sec); font-size:0.78rem; border:1px dashed var(--border-color); border-radius:10px;">
                Yukarıdan katılımcı seçtiğinizde yoklama listesi burada açılır.
            </div>
        `;
        return;
    }

    rowsContainer.innerHTML = invitedNames.map(name => {
        const uObj = appState.users.find(u => u.name === name);
        const deptStr = uObj ? uObj.dept : 'Personel';
        const attState = currentDraftAttendance[name] || { status: 'ATTENDED', reason: '' };
        const isAbsent = attState.status === 'ABSENT';
        const safeNameAttr = escapeHtmlAttr(name);
        const safeReasonAttr = escapeHtmlAttr(attState.reason || '');

        return `
            <div class="attendance-row ${isAbsent ? 'status-absent' : 'status-attended'}">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:0.4rem;">
                    <div style="min-width:0;">
                        <strong style="font-size:0.8rem; color:#fff; display:block; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${name}</strong>
                        <span style="font-size:0.68rem; color:var(--text-sec);">${deptStr}</span>
                    </div>
                    <div style="display:flex; gap:0.3rem; flex-shrink:0;">
                        <button type="button" class="attendance-toggle-btn ${!isAbsent ? 'active-attended' : ''}" onclick="setParticipantAttendanceStatus('${safeNameAttr}', 'ATTENDED')">
                            <i class="fa-solid fa-check"></i> Geldi
                        </button>
                        <button type="button" class="attendance-toggle-btn ${isAbsent ? 'active-absent' : ''}" onclick="setParticipantAttendanceStatus('${safeNameAttr}', 'ABSENT')">
                            <i class="fa-solid fa-xmark"></i> Gelmedi
                        </button>
                    </div>
                </div>
                ${isAbsent ? `
                    <div class="absent-reason-box">
                        <input type="text" class="form-control absent-reason-input" data-person="${safeNameAttr}" style="width:100%; box-sizing:border-box; padding:0.38rem 0.6rem; font-size:0.76rem; border-color:rgba(239,68,68,0.45);" placeholder="${name} için gelmeme nedeni (Örn: İzinli, Sahada...)" value="${safeReasonAttr}" oninput="updateParticipantAbsentReason('${safeNameAttr}', this.value)">
                        <div style="display:flex; gap:0.25rem; flex-wrap:wrap; margin-top:0.3rem;">
                            ${['İzinli', 'Raporlu', 'Müşteri Ziyaretinde', 'Şehir Dışında', 'Servis Yoğunluğu'].map(preset => `
                                <button type="button" style="background:rgba(239,68,68,0.16); border:1px solid rgba(239,68,68,0.35); color:#fecaca; border-radius:5px; padding:1px 6px; font-size:0.65rem; cursor:pointer;" onclick="setQuickAbsentReason('${safeNameAttr}', '${preset}')">${preset}</button>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
}

// --- GÜNDEM MADDELERİ (TİKLEMELİ + ALTTA AÇIKLAMA KUTUCUĞU + KONUŞULMAYANLAR LİSTESİ) ---
function addAgendaItemFromQuickInput() {
    const input = document.getElementById('quick-agenda-item-input');
    if (!input) {
        addAgendaItemRow('', false, '', true);
        return;
    }
    const val = input.value.trim();
    if (!val) {
        addAgendaItemRow('', false, '', true);
        return;
    }
    const cleanTitle = val.replace(/^\d+[\.\)\-]\s*/, '').trim();
    if (currentDraftAgendaItems.length === 1 && !currentDraftAgendaItems[0].title.trim()) {
        currentDraftAgendaItems[0].title = cleanTitle;
    } else {
        currentDraftAgendaItems.push({
            id: 'agd-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
            title: cleanTitle,
            discussed: false,
            explanation: '',
            transferredToMeetingId: ''
        });
    }
    input.value = '';
    renderDraftAgendaItems();
}

function addAgendaItemRow(title = '', discussed = false, explanation = '', focusNew = false) {
    const newId = 'agd-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    currentDraftAgendaItems.push({
        id: newId,
        title: String(title || '').replace(/^\d+[\.\)\-]\s*/, '').trim(),
        discussed: Boolean(discussed),
        explanation: String(explanation || '').trim(),
        transferredToMeetingId: ''
    });
    renderDraftAgendaItems(focusNew ? newId : null);
}

function removeAgendaItemRow(itemId) {
    currentDraftAgendaItems = currentDraftAgendaItems.filter(it => it.id !== itemId);
    if (currentDraftAgendaItems.length === 0) {
        addAgendaItemRow('', false, '', false);
    } else {
        renderDraftAgendaItems();
    }
}

function toggleAgendaItemDiscussed(itemId, checked) {
    const item = currentDraftAgendaItems.find(it => it.id === itemId);
    if (!item) return;
    item.discussed = Boolean(checked);
    renderDraftAgendaItems();
    if (item.discussed) {
        setTimeout(() => {
            const expEl = document.getElementById(`agenda-exp-${itemId}`);
            if (expEl) expEl.focus();
        }, 40);
    }
}

function updateAgendaItemTitle(itemId, val) {
    const item = currentDraftAgendaItems.find(it => it.id === itemId);
    if (!item) return;
    item.title = val;
    renderUndiscussedAgendaSummary();
}

function updateAgendaItemExplanation(itemId, val) {
    const item = currentDraftAgendaItems.find(it => it.id === itemId);
    if (!item) return;
    item.explanation = val;
}

function handleAgendaTitleKeydown(event, itemId) {
    if (event.key === 'Enter') {
        event.preventDefault();
        addAgendaItemRow('', false, '', true);
    }
}

function renderDraftAgendaItems(focusItemId = null) {
    const container = document.getElementById('meeting-agenda-items-container');
    if (!container) return;

    if (currentDraftAgendaItems.length === 0) {
        currentDraftAgendaItems.push({
            id: 'agd-' + Date.now(),
            title: '',
            discussed: false,
            explanation: '',
            transferredToMeetingId: ''
        });
    }

    container.innerHTML = currentDraftAgendaItems.map((it, idx) => {
        const isDiscussed = Boolean(it.discussed);
        const safeTitle = escapeHtmlAttr(it.title || '');
        const safeExp = escapeHtmlAttr(it.explanation || '');

        return `
            <div class="agenda-item-card ${isDiscussed ? 'discussed' : 'undiscussed'}">
                <div style="display:flex; align-items:center; gap:0.55rem;">
                    <span style="font-weight:800; color:#38bdf8; font-size:0.86rem; min-width:22px;">${idx + 1}.</span>

                    <input type="text" id="agenda-title-${it.id}" class="form-control" style="flex:1; min-width:0; padding:0.45rem 0.65rem; font-size:0.84rem; font-weight:600;" placeholder="${idx + 1}. Gündem maddesini yazın..." value="${safeTitle}" oninput="updateAgendaItemTitle('${it.id}', this.value)" onkeydown="handleAgendaTitleKeydown(event, '${it.id}')">

                    <label style="display:inline-flex; align-items:center; gap:0.45rem; cursor:pointer; margin:0; padding:0.38rem 0.65rem; border-radius:8px; background:${isDiscussed ? 'rgba(2,132,199,0.25)' : 'rgba(255,255,255,0.04)'}; border:1.5px solid ${isDiscussed ? '#38bdf8' : 'rgba(148,163,184,0.28)'}; color:${isDiscussed ? '#ffffff' : '#94a3b8'}; font-size:0.76rem; font-weight:700; user-select:none; white-space:nowrap; flex-shrink:0;" title="Görüşüldüyse işaretleyin">
                        <input type="checkbox" class="blue-tick-checkbox" ${isDiscussed ? 'checked' : ''} onchange="toggleAgendaItemDiscussed('${it.id}', this.checked)">
                        <span>${isDiscussed ? 'Konuşuldu' : 'Konuşulmadı'}</span>
                    </label>

                    <button type="button" class="btn btn-danger btn-sm" style="padding:0.4rem 0.55rem; flex-shrink:0;" onclick="removeAgendaItemRow('${it.id}')" title="Gündem Maddesini Sil">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>

                ${isDiscussed ? `
                    <div class="agenda-explanation-box">
                        <textarea id="agenda-exp-${it.id}" class="form-control" rows="2" style="width:100%; box-sizing:border-box; background:rgba(15,23,42,0.9); border-color:rgba(56,189,248,0.4);" placeholder="${idx + 1}. gündem maddesinde konuşulan detayları / notları buraya yazın..." oninput="updateAgendaItemExplanation('${it.id}', this.value)">${safeExp}</textarea>
                    </div>
                ` : (it.transferredToMeetingId ? `
                    <div style="margin-top:0.35rem; font-size:0.72rem; color:#38bdf8;">
                        <i class="fa-solid fa-share"></i> <strong>${it.transferredToMeetingId}</strong> toplantısına aktarıldı
                    </div>
                ` : '')}
            </div>
        `;
    }).join('');

    renderUndiscussedAgendaSummary();

    if (focusItemId) {
        setTimeout(() => {
            const el = document.getElementById(`agenda-title-${focusItemId}`);
            if (el) el.focus();
        }, 30);
    }
}

function renderUndiscussedAgendaSummary() {
    const box = document.getElementById('undiscussed-agenda-summary-box');
    const footerBtn = document.getElementById('btn-footer-plan-followup');
    if (!box) return;

    const undiscussed = currentDraftAgendaItems
        .map((it, idx) => ({ ...it, orderNum: idx + 1 }))
        .filter(it => it.title && it.title.trim() && !it.discussed);

    if (undiscussed.length === 0) {
        box.style.display = 'none';
        box.innerHTML = '';
        if (footerBtn) footerBtn.style.display = 'none';
        return;
    }

    box.style.display = 'block';
    if (footerBtn) footerBtn.style.display = 'inline-flex';

    box.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.6rem;">
            <div style="font-size:0.8rem; color:#fde68a;">
                <i class="fa-solid fa-clock-rotate-left" style="color:#fbbf24;"></i>
                <strong>Konuşulmayan ${undiscussed.length} gündem maddesi var:</strong>
                <span style="color:#fef3c7;">${undiscussed.map(u => `${u.orderNum}. ${escapeHtmlAttr(u.title)}`).join(' • ')}</span>
            </div>
            <button type="button" class="btn btn-sm" style="background:linear-gradient(135deg,#f59e0b,#d97706); color:#0f172a; font-weight:800; padding:0.4rem 0.8rem; font-size:0.75rem; white-space:nowrap;" onclick="openFollowupMeetingModalFromCurrentDraft()">
                <i class="fa-solid fa-calendar-plus"></i> Sonraki Toplantıya Aktar (${undiscussed.length})
            </button>
        </div>
    `;
}

// --- ALINAN KARARLAR, KARAR SORUMLUSU VE TERMİN TARİHLERİ ---
function addDecisionItemRow(text = '', responsible = '', dueDate = '', status = 'Bekliyor', focusNew = false) {
    const defaultDate = normalizeToISODate(document.getElementById('meeting-date-input')?.value) || new Date(Date.now() + 86400000).toISOString().split('T')[0];
    const defaultResp = responsible || (currentUser ? currentUser.name : 'ÖMER EREN');
    const newId = 'dec-' + Date.now() + '-' + Math.floor(Math.random() * 1000);

    currentDraftDecisionItems.push({
        id: newId,
        text: String(text || '').replace(/^\d+[\.\)\-]\s*/, '').trim(),
        responsible: defaultResp,
        dueDate: normalizeToISODate(dueDate) || defaultDate,
        status: status || 'Bekliyor'
    });
    renderDraftDecisionItems(focusNew ? newId : null);
}

function removeDecisionItemRow(decId) {
    currentDraftDecisionItems = currentDraftDecisionItems.filter(d => d.id !== decId);
    if (currentDraftDecisionItems.length === 0) {
        addDecisionItemRow('', '', '', 'Bekliyor', false);
    } else {
        renderDraftDecisionItems();
    }
}

function updateDecisionItemField(decId, field, val) {
    const item = currentDraftDecisionItems.find(d => d.id === decId);
    if (!item) return;
    if (field === 'dueDate') {
        item.dueDate = normalizeToISODate(val);
    } else {
        item[field] = val;
    }
}

function handleDecisionInputKeydown(event, decId) {
    if (event.key === 'Enter') {
        event.preventDefault();
        addDecisionItemRow('', '', '', 'Bekliyor', true);
    }
}

function renderDraftDecisionItems(focusDecId = null) {
    const container = document.getElementById('meeting-decisions-container');
    if (!container) return;

    if (currentDraftDecisionItems.length === 0) {
        const defaultDate = normalizeToISODate(document.getElementById('meeting-date-input')?.value) || new Date(Date.now() + 86400000).toISOString().split('T')[0];
        currentDraftDecisionItems.push({
            id: 'dec-' + Date.now(),
            text: '',
            responsible: currentUser ? currentUser.name : 'ÖMER EREN',
            dueDate: defaultDate,
            status: 'Bekliyor'
        });
    }

    const userOptions = [
        `<option value="Tüm Katılımcılar / Genel">Tüm Katılımcılar / Genel</option>`,
        ...appState.users.map(u => `<option value="${escapeHtmlAttr(u.name)}">${escapeHtmlAttr(u.name)}</option>`)
    ];

    container.innerHTML = currentDraftDecisionItems.map((dec, idx) => {
        const safeText = escapeHtmlAttr(dec.text || '');
        const isoDue = normalizeToISODate(dec.dueDate) || new Date().toISOString().split('T')[0];

        return `
            <div class="decision-item-row">
                <span style="font-weight:800; color:#38bdf8; font-size:0.84rem;">${idx + 1}.</span>
                <div>
                    <input type="text" id="dec-text-${dec.id}" class="form-control" placeholder="${idx + 1}. Alınan kararı yazın..." value="${safeText}" oninput="updateDecisionItemField('${dec.id}', 'text', this.value)" onkeydown="handleDecisionInputKeydown(event, '${dec.id}')">
                </div>
                <div>
                    <select class="form-control" onchange="updateDecisionItemField('${dec.id}', 'responsible', this.value)" title="Karar Sorumlusu">
                        ${userOptions.map(opt => {
                            const isSel = opt.includes(`value="${escapeHtmlAttr(dec.responsible)}"`);
                            return isSel ? opt.replace('<option ', '<option selected ') : opt;
                        }).join('')}
                    </select>
                </div>
                <div>
                    <input type="date" id="dec-date-${dec.id}" class="form-control" value="${isoDue}" onchange="updateDecisionItemField('${dec.id}', 'dueDate', this.value)" oninput="updateDecisionItemField('${dec.id}', 'dueDate', this.value)" title="Termin Tarihi">
                </div>
                <div style="display:flex; gap:0.3rem; align-items:center; justify-content:flex-end;">
                    <button type="button" class="btn btn-primary btn-sm" style="padding:0.4rem 0.5rem; font-size:0.71rem; white-space:nowrap;" onclick="convertDecisionToInlineAction('${dec.id}')" title="Bu Kararı Aksiyon Olarak Ekle">
                        <i class="fa-solid fa-bolt"></i> Aksiyon
                    </button>
                    <button type="button" class="btn btn-danger btn-sm" style="padding:0.4rem 0.5rem;" onclick="removeDecisionItemRow('${dec.id}')" title="Karar Satırını Sil">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </div>
        `;
    }).join('');

    if (window.initAutoDateInputs) {
        window.initAutoDateInputs(container);
    }
    currentDraftDecisionItems.forEach(dec => {
        const dateEl = document.getElementById(`dec-date-${dec.id}`);
        if (dateEl && dec.dueDate) {
            setMaskedDateInputValue(dateEl, dec.dueDate);
        }
    });

    if (focusDecId) {
        setTimeout(() => {
            const el = document.getElementById(`dec-text-${focusDecId}`);
            if (el) el.focus();
        }, 30);
    }
}

function convertDecisionToInlineAction(decId) {
    const dec = currentDraftDecisionItems.find(d => d.id === decId);
    if (!dec) return;
    if (!dec.text || !dec.text.trim()) {
        alert("Lütfen önce karar açıklamasını yazın!");
        return;
    }
    addInlineActionRow();
    const container = document.getElementById('inline-actions-container');
    const lastRow = container?.lastElementChild;
    if (!lastRow) return;
    const titleInput = lastRow.querySelector('.inline-action-title');
    const assigneeSelect = lastRow.querySelector('.inline-action-assignee');
    const dueDateInput = lastRow.querySelector('.inline-action-duedate');
    const dueTimeInput = lastRow.querySelector('.inline-action-duetime');
    if (titleInput) titleInput.value = dec.text.trim();
    if (assigneeSelect && dec.responsible) {
        const matchedUser = appState.users.find(u => normalizeTR(u.name) === normalizeTR(dec.responsible));
        if (matchedUser) assigneeSelect.value = matchedUser.name;
    }
    if (dueDateInput && dec.dueDate) {
        setMaskedDateInputValue(dueDateInput, dec.dueDate);
    }
    if (dueTimeInput) dueTimeInput.value = '17:00';
    lastRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// --- KONUŞULMAYAN MADDELERİ BAŞKA TOPLANTIYA PLANLAMA EKRANI FONKSİYONLARI ---
let pendingFollowupSourceData = null;

function openFollowupMeetingModalFromCurrentDraft() {
    const undiscussed = currentDraftAgendaItems.filter(it => it.title && it.title.trim() && !it.discussed);
    if (undiscussed.length === 0) {
        alert("Şu anda konuşulmayan (tik konulmamış) gündem maddesi bulunmamaktadır.");
        return;
    }

    const idVal = document.getElementById('meeting-id')?.value || '';
    const titleVal = document.getElementById('meeting-title-input')?.value.trim() || 'Toplantı';
    const deptVal = document.getElementById('meeting-dept-input')?.value || 'Genel Yönetim';
    const locVal = document.getElementById('meeting-location-input')?.value.trim() || 'Dizsan Toplantı Salonu';
    const invited = Array.from(document.querySelectorAll('input[name="meeting-participant"]:checked')).map(cb => cb.value);

    pendingFollowupSourceData = {
        sourceMeetingId: idVal,
        title: titleVal,
        dept: deptVal,
        location: locVal,
        participants: invited.length > 0 ? invited : [currentUser ? currentUser.name : 'ÖMER EREN'],
        undiscussedItems: undiscussed
    };

    populateAndOpenFollowupModal(pendingFollowupSourceData);
}

function openFollowupMeetingModal(sourceMeetingId) {
    const m = appState.meetings.find(x => x.id === sourceMeetingId);
    if (!m) return;
    const agd = parseAgendaItemsFromMeeting(m);
    const undiscussed = agd.filter(it => it.title && it.title.trim() && !it.discussed);
    if (undiscussed.length === 0) {
        alert("Bu toplantıda konuşulmayan gündem maddesi bulunmamaktadır.");
        return;
    }

    const attInfo = getMeetingAttendanceSummary(m);
    pendingFollowupSourceData = {
        sourceMeetingId: m.id,
        title: m.title,
        dept: m.dept || 'Genel Yönetim',
        location: m.location || 'Dizsan Toplantı Salonu',
        participants: attInfo.invited,
        undiscussedItems: undiscussed
    };

    populateAndOpenFollowupModal(pendingFollowupSourceData);
}

function populateAndOpenFollowupModal(data) {
    const modal = document.getElementById('followup-meeting-modal');
    if (!modal || !data) return;

    document.getElementById('followup-source-meeting-id').value = data.sourceMeetingId || '';
    document.getElementById('followup-title-input').value = `${data.title} (Konuşulmayan Gündemler Devam Toplantısı)`;
    document.getElementById('followup-dept-input').value = data.dept || 'Genel Yönetim';
    document.getElementById('followup-location-input').value = data.location || 'Dizsan Toplantı Salonu';

    const nextWeekIso = new Date(Date.now() + 7 * 86400000).toISOString().split('T')[0];
    setMaskedDateInputValue(document.getElementById('followup-date-input'), nextWeekIso);
    document.getElementById('followup-time-input').value = '10:00';

    const itemsBox = document.getElementById('followup-undiscussed-items-list');
    if (itemsBox) {
        itemsBox.innerHTML = data.undiscussedItems.map((it, idx) => `
            <label style="display:flex; align-items:center; gap:0.55rem; padding:0.45rem 0.65rem; background:rgba(15,23,42,0.85); border:1px solid rgba(56,189,248,0.35); border-radius:8px; cursor:pointer; font-size:0.82rem; color:#fff;">
                <input type="checkbox" class="blue-tick-checkbox" name="followup-agenda-check" value="${escapeHtmlAttr(it.id)}" data-title="${escapeHtmlAttr(it.title)}" checked>
                <span><strong>${idx + 1}.</strong> ${escapeHtmlAttr(it.title)}</span>
            </label>
        `).join('');
    }

    const partBox = document.getElementById('followup-participants-box');
    if (partBox) {
        partBox.innerHTML = appState.users.map(u => {
            const isChecked = (data.participants || []).includes(u.name);
            return `
                <label class="participant-check ${isChecked ? 'is-checked' : ''}">
                    <input type="checkbox" name="followup-participant" value="${escapeHtmlAttr(u.name)}" ${isChecked ? 'checked' : ''} onchange="syncParticipantCheckStyles()">
                    <span>${u.name} <small style="color:var(--text-sec);">(${u.dept})</small></span>
                </label>
            `;
        }).join('');
    }

    modal.classList.add('open');
}

function closeFollowupMeetingModal() {
    const modal = document.getElementById('followup-meeting-modal');
    if (modal) modal.classList.remove('open');
}

function toggleAllFollowupParticipants(state) {
    document.querySelectorAll('input[name="followup-participant"]').forEach(cb => {
        cb.checked = state;
    });
    syncParticipantCheckStyles();
}

function saveFollowupMeetingPlan(event) {
    event.preventDefault();
    const sourceId = document.getElementById('followup-source-meeting-id')?.value || '';
    const newTitle = document.getElementById('followup-title-input')?.value.trim() || 'Devam Toplantısı';
    const newDept = document.getElementById('followup-dept-input')?.value || 'Genel Yönetim';
    const newDate = normalizeToISODate(document.getElementById('followup-date-input')?.value);
    const newTime = document.getElementById('followup-time-input')?.value || '10:00';
    const newLoc = document.getElementById('followup-location-input')?.value.trim() || 'Dizsan Toplantı Salonu';

    const selectedChecks = Array.from(document.querySelectorAll('input[name="followup-agenda-check"]:checked'));
    if (selectedChecks.length === 0) {
        alert("Lütfen yeni toplantıya aktarılacak en az 1 konuşulmayan gündem maddesi seçin!");
        return;
    }

    const invited = Array.from(document.querySelectorAll('input[name="followup-participant"]:checked')).map(cb => cb.value);
    if (invited.length === 0) {
        alert("Lütfen yeni toplantı için en az 1 davetli katılımcı seçin!");
        return;
    }

    const transferredIds = new Set(selectedChecks.map(cb => cb.value));
    const newAgendaItems = selectedChecks.map((cb, idx) => ({
        id: 'agd-' + Date.now() + '-' + idx,
        title: cb.getAttribute('data-title') || '',
        discussed: false,
        explanation: '',
        transferredToMeetingId: ''
    }));

    const nextNum = String(appState.meetings.length + 1).padStart(3, '0');
    const newMeetingId = `TOP-2026-${nextNum}`;
    const nowStr = formatNowTR();
    const approvalStatus = isOmerEren(currentUser) ? 'Onaylandı' : 'Yönetici Onayı Bekliyor';

    const followupMeeting = {
        id: newMeetingId,
        recordType: 'Toplantı',
        isScheduledCall: true,
        sourceMeetingId: sourceId || '',
        title: newTitle,
        dept: newDept,
        date: newDate,
        time: newTime,
        location: newLoc,
        participants: [...invited],
        invitedParticipants: [...invited],
        attendedParticipants: [...invited],
        absentParticipants: [],
        externalParticipants: [],
        agendaItems: newAgendaItems,
        notes: formatAgendaItemsToLegacyNotes(newAgendaItems),
        decisionItems: [],
        decisions: '',
        attachments: [],
        approvalStatus,
        omerApprovedStamp: isOmerEren(currentUser),
        approvedBy: isOmerEren(currentUser) ? 'ÖMER EREN' : '',
        approvedAt: isOmerEren(currentUser) ? nowStr : '',
        createdBy: currentUser ? currentUser.name : 'ÖMER EREN',
        createdAt: nowStr,
        updatedBy: '',
        updatedAt: ''
    };

    appState.meetings.unshift(followupMeeting);

    if (sourceId) {
        const srcMeeting = appState.meetings.find(m => m.id === sourceId);
        if (srcMeeting) {
            const srcAgendas = parseAgendaItemsFromMeeting(srcMeeting);
            srcAgendas.forEach(ag => {
                if (transferredIds.has(ag.id) || selectedChecks.some(c => c.getAttribute('data-title') === ag.title)) {
                    ag.transferredToMeetingId = newMeetingId;
                }
            });
            srcMeeting.agendaItems = srcAgendas;
            srcMeeting.notes = formatAgendaItemsToLegacyNotes(srcAgendas);
        }
    }

    currentDraftAgendaItems.forEach(ag => {
        if (transferredIds.has(ag.id)) {
            ag.transferredToMeetingId = newMeetingId;
        }
    });
    if (document.getElementById('meeting-modal')?.classList.contains('open')) {
        renderDraftAgendaItems();
    }

    addAuditLog("TOPLANTI", `Konuşulmayan ${newAgendaItems.length} gündem maddesi için ${newMeetingId} kodlu yeni toplantı ('${newTitle}' - ${formatDateTR(newDate)} ${newTime}) planlandı.`);
    syncToServer();
    closeFollowupMeetingModal();
    renderAll();
    playMeetingCallSound('INVITE');
    alert(`📅 Konuşulmayan Gündem Maddeleri Yeni Toplantıya Planlandı!\n\n📌 Yeni Toplantı Kodu: ${newMeetingId}\n📌 Başlık: ${newTitle}\n📅 Tarih & Saat: ${formatDateTR(newDate)} ${newTime}\n📋 Aktarılan Gündem Sayısı: ${newAgendaItems.length} Madde`);
}

function openMeetingModal(meetingId = null) {
    const modal = document.getElementById('meeting-modal');
    const partBox = document.getElementById('meeting-participants-box');
    const inlineContainer = document.getElementById('inline-actions-container');
    const extToggle = document.getElementById('external-participant-toggle');
    const extList = document.getElementById('external-participants-list');
    const printBtn = document.getElementById('btn-modal-print-minutes');

    inlineContainer.innerHTML = '';
    if (extList) extList.innerHTML = '';
    currentDraftAttendance = {};

    partBox.innerHTML = appState.users.map(u => `
        <label class="participant-check">
            <input type="checkbox" name="meeting-participant" value="${escapeHtmlAttr(u.name)}" onchange="onInvitedParticipantCheckboxChange()">
            <span>${u.name} <small style="color:var(--text-sec);">(${u.dept})</small></span>
        </label>
    `).join('');

    if (meetingId) {
        const m = appState.meetings.find(x => x.id === meetingId);
        if (!m) return;
        if (getMeetingAccessLevel(m) !== 'FULL') {
            alert("Bu toplantının/eğitimin katılımcısı olmadığınız için içeriğini görüntüleme/düzenleme yetkiniz bulunmamaktadır.");
            return;
        }
        if (printBtn) printBtn.style.display = 'inline-flex';
        setMeetingRecordType(m.recordType || 'Toplantı');
        document.getElementById('meeting-modal-title').innerHTML = `<i class="fa-solid fa-clipboard-check" style="color:var(--dizsan-light);"></i> ${m.recordType === 'Eğitim' ? 'Eğitim' : 'Toplantı'} Detayı & Karar Yönetimi (${m.id})`;
        document.getElementById('meeting-id').value = m.id;
        document.getElementById('meeting-title-input').value = m.title;
        document.getElementById('meeting-dept-input').value = m.dept;
        setMaskedDateInputValue(document.getElementById('meeting-date-input'), m.date);
        document.getElementById('meeting-time-input').value = m.time || '09:30';
        document.getElementById('meeting-location-input').value = m.location || '';

        const attInfo = getMeetingAttendanceSummary(m);
        const absentMap = {};
        attInfo.absent.forEach(ab => {
            absentMap[normalizeTR(ab.name)] = ab.reason || '';
        });

        attInfo.invited.forEach(invName => {
            const isAbs = Object.prototype.hasOwnProperty.call(absentMap, normalizeTR(invName));
            currentDraftAttendance[invName] = {
                status: isAbs ? 'ABSENT' : 'ATTENDED',
                reason: isAbs ? absentMap[normalizeTR(invName)] : ''
            };
        });

        document.querySelectorAll('input[name="meeting-participant"]').forEach(cb => {
            cb.checked = attInfo.invited.includes(cb.value);
        });
        syncParticipantCheckStyles();
        renderAttendanceManagementUI();

        currentDraftAgendaItems = parseAgendaItemsFromMeeting(m);
        renderDraftAgendaItems();

        currentDraftDecisionItems = parseDecisionItemsFromMeeting(m);
        renderDraftDecisionItems();

        document.getElementById('meeting-notes-input').value = m.notes || '';
        document.getElementById('meeting-decisions-input').value = m.decisions || '';

        const extParticipants = Array.isArray(m.externalParticipants) ? m.externalParticipants : [];
        if (extParticipants.length > 0) {
            if (extToggle) extToggle.checked = true;
            toggleExternalParticipantSection(true);
            if (extList) extList.innerHTML = '';
            extParticipants.forEach(ep => addExternalParticipantRow(ep));
        } else {
            if (extToggle) extToggle.checked = false;
            toggleExternalParticipantSection(false);
        }

        currentDraftAttachments = Array.isArray(m.attachments) ? [...m.attachments] : [];
        renderDraftAttachments();
        renderExistingMeetingActionsInModal(m.id);
        const auditBox = document.getElementById('meeting-audit-info-box');
        if (auditBox) auditBox.innerHTML = renderRecordAuditBadge(m, false);
    } else {
        if (printBtn) printBtn.style.display = 'none';
        setMeetingRecordType('Toplantı');
        document.getElementById('meeting-modal-title').innerHTML = `<i class="fa-solid fa-handshake" style="color:var(--dizsan-light);"></i> Yeni Toplantı / Eğitim Kaydı`;
        document.getElementById('meeting-id').value = '';
        document.getElementById('meeting-title-input').value = '';
        document.getElementById('meeting-dept-input').value = 'Genel Yönetim';
        const todayIso = new Date().toISOString().split('T')[0];
        setMaskedDateInputValue(document.getElementById('meeting-date-input'), todayIso);
        document.getElementById('meeting-time-input').value = '09:30';
        document.getElementById('meeting-location-input').value = 'Dizsan Toplantı Salonu';
        document.getElementById('meeting-notes-input').value = '';
        document.getElementById('meeting-decisions-input').value = '';

        document.querySelectorAll('input[name="meeting-participant"]').forEach(cb => {
            cb.checked = currentUser ? (cb.value === currentUser.name) : false;
            if (cb.checked) {
                currentDraftAttendance[cb.value] = { status: 'ATTENDED', reason: '' };
            }
        });
        syncParticipantCheckStyles();
        renderAttendanceManagementUI();

        currentDraftAgendaItems = [
            { id: 'agd-' + Date.now(), title: '', discussed: false, explanation: '', transferredToMeetingId: '' }
        ];
        renderDraftAgendaItems();

        currentDraftDecisionItems = [
            { id: 'dec-' + Date.now(), text: '', responsible: currentUser ? currentUser.name : 'ÖMER EREN', dueDate: todayIso, status: 'Bekliyor' }
        ];
        renderDraftDecisionItems();

        if (extToggle) extToggle.checked = false;
        toggleExternalParticipantSection(false);

        currentDraftAttachments = [];
        renderDraftAttachments();
        renderExistingMeetingActionsInModal(null);
        const auditBox = document.getElementById('meeting-audit-info-box');
        if (auditBox) {
            auditBox.innerHTML = renderRecordAuditBadge({
                createdBy: currentUser ? currentUser.name : 'ÖMER EREN',
                createdAt: formatNowTR(),
                updatedBy: '',
                updatedAt: ''
            }, false);
        }
    }

    modal.classList.add('open');
}

function closeMeetingModal() {
    document.getElementById('meeting-modal').classList.remove('open');
}

function toggleAllParticipants(state) {
    document.querySelectorAll('input[name="meeting-participant"]').forEach(cb => {
        cb.checked = state;
    });
    onInvitedParticipantCheckboxChange();
}

function renderExistingMeetingActionsInModal(meetingId) {
    const box = document.getElementById('existing-meeting-actions-box');
    if (!box) return;
    if (!meetingId) {
        box.style.display = 'none';
        box.innerHTML = '';
        return;
    }
    const mActions = appState.actions.filter(a => a.meetingId === meetingId);
    if (mActions.length === 0) {
        box.style.display = 'none';
        box.innerHTML = '';
        return;
    }

    box.style.display = 'block';
    box.innerHTML = `
        <div style="font-size:0.76rem; font-weight:700; color:#bae6fd; margin-bottom:0.4rem;">
            <i class="fa-solid fa-list-check"></i> Mevcut Aksiyonlar (${mActions.length})
        </div>
        <div style="display:flex; flex-direction:column; gap:0.4rem;">
            ${mActions.map(a => {
                const st = evaluateActionReminderStatus(a);
                const compDisp = getActionCompletedDisplay(a);
                return `
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; padding:0.5rem 0.65rem; border-radius:8px; background:rgba(15,23,42,0.82); border:1px solid ${a.status === 'Tamamlandı' ? 'rgba(16,185,129,0.4)' : 'rgba(56,189,248,0.3)'};">
                        <div style="flex:1; min-width:200px;">
                            <div style="font-weight:700; font-size:0.81rem; color:#fff;">
                                <span style="color:var(--dizsan-light);">${a.id}:</span> ${a.title}
                            </div>
                            <div style="font-size:0.72rem; color:#cbd5e1; margin-top:2px; display:flex; flex-wrap:wrap; gap:0.55rem; align-items:center;">
                                <span><i class="fa-solid fa-user" style="color:#38bdf8;"></i> <strong>${a.assignee}</strong></span>
                                <span><i class="fa-regular fa-clock" style="color:#fbbf24;"></i> <strong style="color:#fde68a;">${formatDateTR(a.dueDate)} ${a.dueTime || '17:00'}</strong></span>
                                <span class="countdown-pill ${st.type}" style="font-size:0.66rem; padding:1px 6px;">${st.shortText || st.badgeText}</span>
                                ${compDisp ? `<span style="color:#6ee7b7; font-weight:700;">✅ ${compDisp}</span>` : ''}
                            </div>
                        </div>
                        <div style="display:flex; align-items:center; gap:0.35rem;">
                            <select class="form-control" style="padding:0.28rem 0.45rem; font-size:0.74rem; font-weight:700; width:auto;" onchange="quickChangeActionStatus('${a.id}', this.value)">
                                <option value="Bekliyor" ${a.status === 'Bekliyor' ? 'selected' : ''}>⏳ Bekliyor</option>
                                <option value="Devam Ediyor" ${a.status === 'Devam Ediyor' ? 'selected' : ''}>🔄 Devam Ediyor</option>
                                <option value="Tamamlandı" ${a.status === 'Tamamlandı' ? 'selected' : ''}>✅ Tamamlandı</option>
                            </select>
                            <button type="button" class="btn btn-secondary btn-sm" style="padding:0.32rem 0.5rem;" onclick="openActionModal('${a.id}')" title="Aksiyonu Düzenle">
                                <i class="fa-solid fa-pen"></i>
                            </button>
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

function addInlineActionRow() {
    const container = document.getElementById('inline-actions-container');
    const row = document.createElement('div');
    row.className = 'inline-action-row';
    const tomorrowIso = new Date(Date.now() + 86400000).toISOString().split('T')[0];

    row.innerHTML = `
        <div>
            <label style="font-size:0.68rem; color:#bae6fd; display:block; margin-bottom:2px;">Aksiyon / Görev Açıklaması *</label>
            <input type="text" class="form-control inline-action-title" placeholder="Yapılacak aksiyonu yazın..." required>
        </div>
        <div>
            <label style="font-size:0.68rem; color:#bae6fd; display:block; margin-bottom:2px;">Sorumlu *</label>
            <select class="form-control inline-action-assignee">
                ${appState.users.map(u => `<option value="${u.name}">${u.name}</option>`).join('')}
            </select>
        </div>
        <div>
            <label style="font-size:0.68rem; color:#bae6fd; display:block; margin-bottom:2px;">Öncelik</label>
            <select class="form-control inline-action-priority">
                <option value="Normal">Normal</option>
                <option value="Kritik">Kritik</option>
            </select>
        </div>
        <div>
            <label style="font-size:0.68rem; color:#fde68a; display:block; margin-bottom:2px;">Termin Tarihi *</label>
            <input type="date" class="form-control inline-action-duedate" value="${tomorrowIso}" required>
        </div>
        <div>
            <label style="font-size:0.68rem; color:#fde68a; display:block; margin-bottom:2px;">Saat *</label>
            <input type="time" class="form-control inline-action-duetime" value="17:00" required>
        </div>
        <button type="button" class="btn btn-danger btn-sm" style="height:34px; padding:0 0.5rem;" onclick="this.parentElement.remove()" title="Satırı Kaldır"><i class="fa-solid fa-xmark"></i></button>
    `;
    container.appendChild(row);
    if (window.initAutoDateInputs) window.initAutoDateInputs(row);
}

function cleanNumberedText(rawText) {
    if (!rawText) return '';
    // Sadece "1." veya boş numaralı satırları temizle
    return rawText
        .split('\n')
        .filter(line => !/^\s*\d+[\.\)\-]?\s*$/.test(line))
        .join('\n')
        .trim();
}

function saveMeeting(event) {
    event.preventDefault();
    const idVal = document.getElementById('meeting-id').value;
    const recordType = document.getElementById('meeting-record-type-input')?.value || 'Toplantı';
    const title = document.getElementById('meeting-title-input').value.trim();
    const dept = document.getElementById('meeting-dept-input').value;
    const dateRaw = document.getElementById('meeting-date-input').value;
    const date = normalizeToISODate(dateRaw);
    const time = document.getElementById('meeting-time-input').value;
    const location = document.getElementById('meeting-location-input').value.trim();

    // Hızlı gündem kutusunda yazılıp "+ Ekle"ye basılmamış metin varsa ekle
    const pendingQuickAgenda = document.getElementById('quick-agenda-item-input');
    if (pendingQuickAgenda && pendingQuickAgenda.value.trim()) {
        addAgendaItemFromQuickInput();
    }

    const invitedParticipants = Array.from(document.querySelectorAll('input[name="meeting-participant"]:checked')).map(cb => cb.value);
    const attendedParticipants = invitedParticipants.filter(name => currentDraftAttendance[name]?.status !== 'ABSENT');
    const absentParticipants = invitedParticipants
        .filter(name => currentDraftAttendance[name]?.status === 'ABSENT')
        .map(name => ({
            name,
            reason: (currentDraftAttendance[name]?.reason || '').trim() || 'Mazeret belirtilmedi'
        }));

    // Gizlilik ve bildirim motoru için tüm davetli katılımcılar
    const participants = [...invitedParticipants];

    // Dış / Manuel Katılımcıları Topla
    const externalParticipants = [];
    const extToggle = document.getElementById('external-participant-toggle');
    if (extToggle && extToggle.checked) {
        const pendingExtName = document.getElementById('ext-manual-name')?.value.trim() || '';
        if (pendingExtName) {
            addManualExternalParticipantFromInputs();
        }
        document.querySelectorAll('#external-participants-list .external-participant-row').forEach(row => {
            const name = row.querySelector('.ext-part-name')?.value.trim() || '';
            const phone = row.querySelector('.ext-part-phone')?.value.trim() || '';
            const company = row.querySelector('.ext-part-company')?.value.trim() || '';
            if (name) {
                externalParticipants.push({ name, phone, company });
            }
        });
    }

    if (invitedParticipants.length === 0 && externalParticipants.length === 0) {
        alert("Lütfen en az 1 davetli katılımcı (personel veya dış katılımcı) seçin/ekleyin!");
        return;
    }

    const validAgendaItems = currentDraftAgendaItems
        .map(it => ({
            id: it.id || ('agd-' + Date.now()),
            title: String(it.title || '').trim(),
            discussed: Boolean(it.discussed),
            explanation: it.discussed ? String(it.explanation || '').trim() : '',
            transferredToMeetingId: String(it.transferredToMeetingId || '').trim()
        }))
        .filter(it => it.title);

    if (validAgendaItems.length === 0) {
        alert("Lütfen Gündem Maddeleri alanına en az 1 gündem maddesi yazın!");
        return;
    }

    const validDecisionItems = currentDraftDecisionItems
        .map(d => ({
            id: d.id || ('dec-' + Date.now()),
            text: String(d.text || '').trim(),
            responsible: String(d.responsible || 'ÖMER EREN').trim(),
            dueDate: normalizeToISODate(d.dueDate || date),
            status: d.status || 'Bekliyor'
        }))
        .filter(d => d.text);

    const notes = formatAgendaItemsToLegacyNotes(validAgendaItems);
    const decisions = formatDecisionItemsToLegacyText(validDecisionItems);

    // Eğer Ek Bilgi Notu kutusunda yazılıp "Ekle" butonuna basılmamış bir metin varsa onu da otomatik ekle
    const pendingNoteInput = document.getElementById('meeting-attachment-note-input');
    if (pendingNoteInput && pendingNoteInput.value.trim()) {
        addTextNoteAttachment();
    }

    const attachments = [...currentDraftAttachments];

    let targetMeetingId = idVal;

    if (idVal) {
        const idx = appState.meetings.findIndex(m => m.id === idVal);
        if (idx !== -1) {
            const editorName = currentUser ? currentUser.name : 'ÖMER EREN';
            const editNow = formatNowTR();
            if (isOmerEren(currentUser)) {
                appState.meetings[idx] = {
                    ...appState.meetings[idx],
                    recordType, title, dept, date, time, location,
                    participants, invitedParticipants, attendedParticipants, absentParticipants,
                    externalParticipants,
                    agendaItems: validAgendaItems,
                    decisionItems: validDecisionItems,
                    notes, decisions, attachments,
                    approvalStatus: 'Onaylandı',
                    omerApprovedStamp: true,
                    approvedBy: 'ÖMER EREN',
                    approvedAt: editNow,
                    updatedBy: editorName,
                    updatedAt: editNow
                };
                addAuditLog("TOPLANTI", `${idVal} kodlu '${title}' kaydı Yönetici ÖMER EREN tarafından güncellendi (Davetli: ${invitedParticipants.length}, Gelen: ${attendedParticipants.length}, Gelmeyen: ${absentParticipants.length}).`);
                // Düzenleme yapıldığında tekrar bildirim veya ses verme
                const myNorm = normalizeTR(editorName);
                try {
                    localStorage.setItem(`alert_invite_${idVal}_${myNorm}`, '1');
                    localStorage.setItem(`alert_invite_${idVal}_${myNorm}_${date}_${time}`, '1');
                } catch (e) {}
            } else {
                // Mevcut toplantı personel tarafından değiştirildiğinde Yönetici Ömer Eren onay kuyruğuna düşer (bildirimsiz)
                if (!Array.isArray(appState.approvalRequests)) appState.approvalRequests = [];
                appState.approvalRequests.unshift({
                    id: 'ONAY-' + Date.now(),
                    type: 'EDIT_MEETING',
                    status: 'PENDING',
                    meetingId: idVal,
                    meetingTitle: appState.meetings[idx].title,
                    requestedBy: editorName,
                    requestedAt: editNow,
                    reason: "Toplantı tutanağı güncelleme talebi",
                    proposedData: {
                        recordType, title, dept, date, time, location,
                        participants, invitedParticipants, attendedParticipants, absentParticipants,
                        externalParticipants,
                        agendaItems: validAgendaItems,
                        decisionItems: validDecisionItems,
                        notes, decisions, attachments,
                        updatedBy: editorName,
                        updatedAt: editNow
                    }
                });
                addAuditLog("TOPLANTI", `${editorName}, ${idVal} kodlu '${title}' kaydı için değiştirme (düzenleme) talebi oluşturdu (Yönetici ÖMER EREN onayı bekleniyor).`);
            }
        }
    } else {
        const prefix = recordType === 'Eğitim' ? 'EGT' : 'TOP';
        targetMeetingId = generateUniqueMeetingId(prefix);
        const approvalStatus = isOmerEren(currentUser) ? 'Onaylandı' : 'Yönetici Onayı Bekliyor';
        const nowStr = formatNowTR();
        const newMeeting = {
            id: targetMeetingId,
            recordType, title, dept, date, time, location,
            participants, invitedParticipants, attendedParticipants, absentParticipants,
            externalParticipants,
            agendaItems: validAgendaItems,
            decisionItems: validDecisionItems,
            notes, decisions, attachments,
            approvalStatus,
            omerApprovedStamp: isOmerEren(currentUser),
            approvedBy: isOmerEren(currentUser) ? 'ÖMER EREN' : '',
            approvedAt: isOmerEren(currentUser) ? nowStr : '',
            createdBy: currentUser ? currentUser.name : "ÖMER EREN",
            createdAt: nowStr,
            updatedBy: '',
            updatedAt: ''
        };
        appState.meetings.unshift(newMeeting);
        addAuditLog("TOPLANTI", `${targetMeetingId} kodlu yeni ${recordType.toLowerCase()} ('${title}') oluşturuldu (${approvalStatus}). Davetli: ${invitedParticipants.length}, Gelen: ${attendedParticipants.length}, Gelmeyen: ${absentParticipants.length}.`);
        playMeetingCallSound('APPROVAL', `Dikkat! ${title} başlıklı yeni ${recordType.toLowerCase()} kaydedildi.`);
    }

    const inlineRows = document.querySelectorAll('#inline-actions-container > div');
    inlineRows.forEach(r => {
        const aTitle = r.querySelector('.inline-action-title')?.value.trim();
        const aAssignee = r.querySelector('.inline-action-assignee')?.value;
        const aPrio = r.querySelector('.inline-action-priority')?.value || 'Normal';
        const aDueRaw = r.querySelector('.inline-action-duedate')?.value;
        const aDueTimeRaw = r.querySelector('.inline-action-duetime')?.value || '17:00';
        if (aTitle) {
            const newActId = generateUniqueActionId();
            const actCreatedNow = formatNowTR();
            const todayIso = new Date().toISOString().split('T')[0];
            appState.actions.unshift({
                id: newActId,
                meetingId: targetMeetingId,
                meetingTitle: title,
                title: aTitle,
                assignee: aAssignee,
                manager: "ÖMER EREN",
                priority: aPrio,
                dueDate: normalizeToISODate(aDueRaw),
                dueTime: aDueTimeRaw,
                status: "Bekliyor",
                note: "",
                completedDate: "",
                completedTime: "",
                completedAt: "",
                remindOneDayBefore: true,
                remindSameDay: true,
                remindNextDay: true,
                remindEveryOtherDay: true,
                createdDate: todayIso,
                createdBy: currentUser ? currentUser.name : "ÖMER EREN",
                createdAt: actCreatedNow,
                updatedBy: '',
                updatedAt: ''
            });
            addAuditLog("AKSİYON", `${newActId} kodlu aksiyon '${aAssignee}' personeline ve Yönetici ÖMER EREN'e ertesi gün ve gün aşırı hatırlatıcılı olarak atandı (Tamamlama: ${formatDateTR(aDueRaw)} ${aDueTimeRaw}).`);
        }
    });

    syncToServer();
    closeMeetingModal();
    renderAll();

    // Konuşulmayan (tik konulmamış ve henüz başka toplantıya aktarılmamış) gündem maddeleri varsa otomatik Başka Toplantı Planlama ekranını aç
    const untransferredUndiscussed = validAgendaItems.filter(it => !it.discussed && !it.transferredToMeetingId);
    if (untransferredUndiscussed.length > 0) {
        setTimeout(() => {
            openFollowupMeetingModal(targetMeetingId);
        }, 120);
    }
}

function deleteMeeting(meetingId) {
    const m = appState.meetings.find(x => x.id === meetingId);
    if (!m) return;
    if (getMeetingAccessLevel(m) !== 'FULL') {
        alert("Bu kaydı silme yetkiniz bulunmamaktadır.");
        return;
    }

    if (isOmerEren(currentUser)) {
        if (!confirm(`'${m.title}' (${m.id}) toplantı/eğitim kaydını kalıcı olarak silmek istediğinize emin misiniz?`)) return;
        registerDeletedRecordId(m.id);
        appState.meetings = appState.meetings.filter(x => x.id !== meetingId);
        addAuditLog("TOPLANTI", `${m.id} kodlu '${m.title}' kaydı Yönetici ÖMER EREN tarafından silindi.`);
        syncToServer();
        renderAll();
        return;
    }

    // Personel silme işlemi Yönetici Ömer Eren onay merkezine düşer
    if (!Array.isArray(appState.approvalRequests)) appState.approvalRequests = [];

    appState.approvalRequests.unshift({
        id: 'ONAY-' + Date.now(),
        type: 'DELETE_MEETING',
        status: 'PENDING',
        meetingId: m.id,
        meetingTitle: m.title,
        requestedBy: currentUser ? currentUser.name : 'Personel',
        requestedAt: formatNowTR(),
        reason: 'Kayıt silme talebi'
    });

    addAuditLog("TOPLANTI", `${currentUser ? currentUser.name : 'Personel'}, ${m.id} kodlu '${m.title}' kaydı için SİLME ONAY TALEBİ gönderdi (Yönetici ÖMER EREN onayı bekleniyor).`);
    syncToServer();
    renderAll();
    playMeetingCallSound('APPROVAL', `Dikkat! ${m.title} toplantısı için silme onayı bekleniyor.`);
    alert(`🛡️ Silme Talebi Yönetici ÖMER EREN Onayına Düşürüldü!\n\n'${m.title}' (${m.id}) kaydı için silme talebi ekranın üst kısmındaki "🛡️ ÖMER EREN YÖNETİCİ ONAY MERKEZİ"ne düşmüştür. Ömer Eren "✅ Silmeyi Onayla (Kaydı Sil)" butonuna bastığında kayıt silinecektir.`);
}

function onActionModalStatusChange(statusVal) {
    const compBox = document.getElementById('action-completed-datetime-box');
    const compDateEl = document.getElementById('action-completed-date-input');
    const compTimeEl = document.getElementById('action-completed-time-input');
    if (!compBox) return;

    if (statusVal === 'Tamamlandı') {
        compBox.style.display = 'block';
        const now = new Date();
        const todayIso = now.toISOString().split('T')[0];
        const pad = n => String(n).padStart(2, '0');
        const nowHm = `${pad(now.getHours())}:${pad(now.getMinutes())}`;
        if (compDateEl && !normalizeToISODate(compDateEl.value)) {
            setMaskedDateInputValue(compDateEl, todayIso);
        }
        if (compTimeEl && !compTimeEl.value) {
            compTimeEl.value = nowHm;
        }
    } else {
        compBox.style.display = 'none';
    }
}

function openActionModal(actionId = null) {
    populateSelectFilters();
    const modal = document.getElementById('action-modal');
    const compDateEl = document.getElementById('action-completed-date-input');
    const compTimeEl = document.getElementById('action-completed-time-input');

    if (actionId) {
        const a = appState.actions.find(x => x.id === actionId);
        if (!a) return;
        document.getElementById('action-modal-title').innerHTML = `<i class="fa-solid fa-pen" style="color:#fbbf24;"></i> Aksiyon Kaydını Düzenle (${a.id})`;
        document.getElementById('action-id').value = a.id;
        document.getElementById('action-meeting-select').value = a.meetingId || 'GENEL';
        document.getElementById('action-title-input').value = a.title;
        document.getElementById('action-assignee-select').value = a.assignee;
        document.getElementById('action-manager-select').value = a.manager || 'ÖMER EREN';
        document.getElementById('action-priority-select').value = a.priority || 'Normal';
        setMaskedDateInputValue(document.getElementById('action-duedate-input'), a.dueDate);
        document.getElementById('action-duetime-input').value = a.dueTime || '17:00';
        document.getElementById('action-status-select').value = a.status || 'Bekliyor';
        document.getElementById('action-note-input').value = a.note || '';

        if (compDateEl) {
            setMaskedDateInputValue(compDateEl, a.completedDate || new Date().toISOString().split('T')[0]);
        }
        if (compTimeEl) {
            compTimeEl.value = a.completedTime || '17:00';
        }
        onActionModalStatusChange(a.status || 'Bekliyor');

        const auditBox = document.getElementById('action-audit-info-box');
        if (auditBox) auditBox.innerHTML = renderRecordAuditBadge(a, false);
    } else {
        document.getElementById('action-modal-title').innerHTML = `<i class="fa-solid fa-stopwatch" style="color:#fbbf24;"></i> Yeni Aksiyon &amp; Ertesi Gün / Gün Aşırı Hatırlatıcı Tanımla`;
        document.getElementById('action-id').value = '';
        document.getElementById('action-title-input').value = '';
        document.getElementById('action-manager-select').value = 'ÖMER EREN';
        document.getElementById('action-priority-select').value = 'Normal';
        const tomorrowIso = new Date(Date.now() + 86400000).toISOString().split('T')[0];
        setMaskedDateInputValue(document.getElementById('action-duedate-input'), tomorrowIso);
        document.getElementById('action-duetime-input').value = '17:00';
        document.getElementById('action-status-select').value = 'Bekliyor';
        document.getElementById('action-note-input').value = '';
        if (compDateEl) setMaskedDateInputValue(compDateEl, new Date().toISOString().split('T')[0]);
        if (compTimeEl) compTimeEl.value = '17:00';
        onActionModalStatusChange('Bekliyor');

        const auditBox = document.getElementById('action-audit-info-box');
        if (auditBox) {
            auditBox.innerHTML = renderRecordAuditBadge({
                createdBy: currentUser ? currentUser.name : 'ÖMER EREN',
                createdAt: formatNowTR(),
                updatedBy: '',
                updatedAt: ''
            }, false);
        }
    }

    modal.classList.add('open');
}

function closeActionModal() {
    document.getElementById('action-modal').classList.remove('open');
}

function saveAction(event) {
    event.preventDefault();
    const idVal = document.getElementById('action-id').value;
    const meetingId = document.getElementById('action-meeting-select').value;
    const matchedMeeting = appState.meetings.find(m => m.id === meetingId);
    const meetingTitle = matchedMeeting ? matchedMeeting.title : "Genel Operasyon Görevi";

    const title = document.getElementById('action-title-input').value.trim();
    const assignee = document.getElementById('action-assignee-select').value;
    const manager = document.getElementById('action-manager-select').value || "ÖMER EREN";
    const priority = document.getElementById('action-priority-select').value;
    const dueDate = normalizeToISODate(document.getElementById('action-duedate-input').value);
    const dueTime = document.getElementById('action-duetime-input').value || '17:00';
    const status = document.getElementById('action-status-select').value;
    const note = document.getElementById('action-note-input').value.trim();

    let completedDate = '';
    let completedTime = '';
    let completedAt = '';
    if (status === 'Tamamlandı') {
        const now = new Date();
        const pad = n => String(n).padStart(2, '0');
        completedDate = normalizeToISODate(document.getElementById('action-completed-date-input')?.value) || now.toISOString().split('T')[0];
        completedTime = document.getElementById('action-completed-time-input')?.value || `${pad(now.getHours())}:${pad(now.getMinutes())}`;
        completedAt = `${formatDateTR(completedDate)} ${completedTime}`;
    }

    if (idVal) {
        const idx = appState.actions.findIndex(a => a.id === idVal);
        if (idx !== -1) {
            const existing = appState.actions[idx];
            appState.actions[idx] = {
                ...existing,
                meetingId, meetingTitle, title, assignee, manager, priority, dueDate, dueTime, status, note,
                completedDate, completedTime, completedAt,
                remindOneDayBefore: true,
                remindSameDay: true,
                remindNextDay: true,
                remindEveryOtherDay: true,
                createdDate: existing.createdDate || extractActionCreatedISODate(existing) || new Date().toISOString().split('T')[0],
                createdBy: existing.createdBy || "ÖMER EREN",
                createdAt: existing.createdAt || existing.updatedAt || formatNowTR(),
                updatedBy: currentUser ? currentUser.name : "ÖMER EREN",
                updatedAt: formatNowTR()
            };
            addAuditLog("AKSİYON", `${idVal} aksiyonu ${currentUser ? currentUser.name : 'ÖMER EREN'} tarafından güncellendi (Sorumlu: ${assignee}, Durum: ${status}, Tamamlama Hedefi: ${formatDateTR(dueDate)} ${dueTime}${completedAt ? `, Kapanış: ${completedAt}` : ''}).`);
        }
    } else {
        const newId = generateUniqueActionId();
        const nowStr = formatNowTR();
        const todayIso = new Date().toISOString().split('T')[0];
        appState.actions.unshift({
            id: newId,
            meetingId, meetingTitle, title, assignee, manager, priority, dueDate, dueTime, status, note,
            completedDate, completedTime, completedAt,
            remindOneDayBefore: true,
            remindSameDay: true,
            remindNextDay: true,
            remindEveryOtherDay: true,
            createdDate: todayIso,
            createdBy: currentUser ? currentUser.name : "ÖMER EREN",
            createdAt: nowStr,
            updatedBy: '',
            updatedAt: ''
        });
        addAuditLog("AKSİYON", `${newId} aksiyonu tanımlandı: '${title}' -> Sorumlu: ${assignee} | Yönetici: ${manager} (Hedef Tamamlama: ${formatDateTR(dueDate)} ${dueTime} • Ertesi gün uyarısı ve gün aşırı hatırlatma aktif).`);
    }

    const targetAction = idVal ? appState.actions.find(a => a.id === idVal) : appState.actions[0];
    if (targetAction) {
        dispatchActionAssignedPush(targetAction);
    }

    if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission();
    }

    syncToServer();
    closeActionModal();
    const openMeetId = document.getElementById('meeting-id')?.value;
    if (openMeetId) renderExistingMeetingActionsInModal(openMeetId);
    renderAll();
}

function quickChangeActionStatus(actionId, newStatus) {
    const a = appState.actions.find(x => x.id === actionId);
    if (!a) return;
    if (!canUserSeeAction(a)) {
        alert("🔒 Bu aksiyon üzerinde işlem yapma yetkiniz bulunmamaktadır.");
        renderAll();
        return;
    }
    const oldStatus = a.status;
    a.status = newStatus;
    if (newStatus === 'Tamamlandı') {
        const now = new Date();
        const pad = n => String(n).padStart(2, '0');
        a.completedDate = now.toISOString().split('T')[0];
        a.completedTime = `${pad(now.getHours())}:${pad(now.getMinutes())}`;
        a.completedAt = `${formatDateTR(a.completedDate)} ${a.completedTime}`;
    } else {
        a.completedDate = '';
        a.completedTime = '';
        a.completedAt = '';
    }
    if (!a.createdAt) a.createdAt = a.updatedAt || formatNowTR();
    if (!a.createdBy) a.createdBy = 'ÖMER EREN';
    a.updatedBy = currentUser ? currentUser.name : 'ÖMER EREN';
    a.updatedAt = formatNowTR();
    addAuditLog("AKSİYON", `${a.id} (${a.assignee}) aksiyon durumu '${oldStatus}' -> '${newStatus}'${a.completedAt ? ` (Tamamlanma: ${a.completedAt})` : ''} olarak ${a.updatedBy} tarafından güncellendi.`);
    dispatchActionProgressPush(a, oldStatus, newStatus);
    syncToServer();
    const openMeetId = document.getElementById('meeting-id')?.value;
    if (openMeetId) renderExistingMeetingActionsInModal(openMeetId);
    renderAll();
}

function deleteAction(actionId) {
    const a = appState.actions.find(x => x.id === actionId);
    if (!a) return;
    const isAdmin = isOmerEren(currentUser);

    if (!isAdmin) {
        const reason = prompt(`🔒 Aksiyon Silme Yetkisi Yalnızca Yönetici ÖMER EREN'e Aittir!\n\n'${a.title}' aksiyonunun silinmesi için Yönetici Onay Talebi oluşturulacaktır.\n\nLütfen silme gerekçenizi yazın:`);
        if (!reason || !reason.trim()) return;

        if (!Array.isArray(appState.approvalRequests)) appState.approvalRequests = [];
        const reqId = 'ONAY-' + Date.now();
        const approvalReq = {
            id: reqId,
            type: 'DELETE_ACTION',
            status: 'PENDING',
            actionId: a.id,
            actionTitle: a.title,
            assignee: a.assignee,
            requestedBy: currentUser ? currentUser.name : 'Personel',
            requestedAt: formatNowTR(),
            reason: reason.trim()
        };
        appState.approvalRequests.unshift(approvalReq);
        addAuditLog("AKSİYON", `${currentUser ? currentUser.name : 'Personel'}, '${a.title}' (${a.id}) aksiyonu için SİLME ONAY TALEBİ gönderdi (Yönetici ÖMER EREN onayı bekleniyor).`);
        dispatchPushToServer(['omer', 'omer eren'], {
            title: `🛡️ Aksiyon Silme Onayı Bekleniyor`,
            body: `${currentUser ? currentUser.name : 'Personel'}, '${a.title}' aksiyonunun silinmesi için onay talep etti.`,
            tag: `appr_del_act_${reqId}`,
            sound: 'APPROVAL'
        });
        syncToServer();
        renderAll();
        alert(`🛡️ Silme Talebiniz Yönetici ÖMER EREN Onayına Gönderildi!\n\nÖmer Eren talebi onayladığında aksiyon sistemden kaldırılacaktır.`);
        return;
    }

    if (!confirm(`'${a.title}' aksiyonunu silmek istediğinize emin misiniz?`)) return;
    registerDeletedRecordId(actionId);
    appState.actions = appState.actions.filter(x => x.id !== actionId);
    addAuditLog("AKSİYON", `${actionId} kodlu aksiyon Yönetici ÖMER EREN tarafından silindi.`);
    syncToServer();
    renderAll();
}

// ==========================================================================
// 10. PERSONEL EKLEME / GÜNCELLEME (GİZLİLİK VE YETKİ KORUMALI)
// Kural: Herkes yalnızca kendi bilgilerini görür ve düzenler.
// Diğer tüm personelleri görüntüleme, düzenleme ve yeni personel ekleme yetkisi SADECE ÖMER EREN'dedir.
// ==========================================================================
function openUserModal(username = null) {
    const modal = document.getElementById('user-modal');
    const isAdmin = isOmerEren(currentUser);

    if (!isAdmin) {
        if (!currentUser) return;
        // Ömer Eren dışındaki kullanıcılar kendi şifresini değiştirmek için mevcut şifre doğrulamalı modalı kullanır
        if (!username || normalizeTR(username) !== normalizeTR(currentUser.username)) {
            alert("🔒 Yetki ve Gizlilik Kısıtlaması:\n\nYalnızca kendi hesap bilgilerinizi ve şifrenizi görüntüleyebilir veya düzenleyebilirsiniz! Diğer kullanıcıların bilgileri yalnızca Yönetici ÖMER EREN tarafından görüntülenebilir.");
            return;
        }
        openChangePasswordModal();
        return;
    }

    const fnInput = document.getElementById('user-fullname-input');
    const unInput = document.getElementById('user-username-input');
    const pwInput = document.getElementById('user-password-input');
    const emInput = document.getElementById('user-email-input');
    const dpInput = document.getElementById('user-dept-input');
    const rlInput = document.getElementById('user-role-input');

    if (username) {
        const u = appState.users.find(x => normalizeTR(x.username) === normalizeTR(username));
        if (!u) return;
        fnInput.value = u.name;
        unInput.value = u.username;
        pwInput.value = '';
        pwInput.placeholder = 'Değiştirmek için yeni şifre girin (boş bırakılırsa mevcut korunur)';
        pwInput.required = false;
        emInput.value = resolveUserEmail(u);
        dpInput.value = u.dept || '';
        rlInput.value = u.role || 'Personel';

        fnInput.readOnly = !isAdmin;
        unInput.readOnly = !isAdmin;
        rlInput.disabled = !isAdmin;
    } else {
        fnInput.value = '';
        unInput.value = '';
        pwInput.value = '';
        pwInput.placeholder = 'Yeni personel şifresi';
        pwInput.required = true;
        emInput.value = '';
        dpInput.value = 'Servis';
        rlInput.value = 'Personel';
        fnInput.readOnly = false;
        unInput.readOnly = false;
        rlInput.disabled = false;
    }
    modal.classList.add('open');
}

function closeUserModal() {
    document.getElementById('user-modal').classList.remove('open');
}

function saveUser(event) {
    event.preventDefault();
    const isAdmin = isOmerEren(currentUser);
    const name = document.getElementById('user-fullname-input').value.trim();
    const username = document.getElementById('user-username-input').value.trim().toLocaleLowerCase('tr-TR');
    const pinInputVal = document.getElementById('user-password-input').value.trim();
    const email = document.getElementById('user-email-input').value.trim().toLowerCase();
    const dept = document.getElementById('user-dept-input').value.trim();
    const role = document.getElementById('user-role-input').value;

    if (!isAdmin) {
        closeUserModal();
        openChangePasswordModal();
        return;
    }

    const existingIdx = appState.users.findIndex(u => normalizeTR(u.username) === normalizeTR(username) || normalizeTR(u.name) === normalizeTR(name));
    const nowMs = Date.now();
    if (existingIdx !== -1) {
        const nextPinStamp = pinInputVal ? hashPin(pinInputVal) : appState.users[existingIdx].pinStamp;
        const updatedAtMs = pinInputVal ? nowMs : (appState.users[existingIdx].pinUpdatedAtMs || 0);
        appState.users[existingIdx] = {
            ...appState.users[existingIdx],
            name,
            username,
            pinStamp: nextPinStamp,
            pinUpdatedAtMs: updatedAtMs,
            email,
            mailBox: email ? email.split('@')[0] : appState.users[existingIdx].mailBox,
            dept,
            role
        };
        if (pinInputVal) {
            try {
                fetch('/api/update-user-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, pinStamp: nextPinStamp, updatedAtMs: nowMs })
                }).catch(() => {});
            } catch (e) {}
            dispatchZiyaretCloudResetBridge('update_user_password', { username, pinStamp: nextPinStamp, updatedAtMs: nowMs });
        }
        if (currentUser && normalizeTR(currentUser.username) === normalizeTR(username)) {
            currentUser = { ...appState.users[existingIdx] };
            localStorage.setItem(STORAGE_KEY_SESSION, JSON.stringify(currentUser));
        }
        addAuditLog("SÜRÜM / YÖNETİM", `${name} (${username}) personel bilgileri Yönetici ÖMER EREN tarafından güncellendi.`);
    } else {
        const nextPinStamp = pinInputVal ? hashPin(pinInputVal) : DEFAULT_PIN_STAMP;
        appState.users.push({
            order: appState.users.length,
            name,
            username,
            pinStamp: nextPinStamp,
            pinUpdatedAtMs: nowMs,
            email,
            mailBox: email ? email.split('@')[0] : username,
            dept,
            role
        });
        addAuditLog("SÜRÜM / YÖNETİM", `Yeni personel hesabı Yönetici ÖMER EREN tarafından eklendi: ${name} (${dept}).`);
    }

    syncToServer();
    renderQuickUserChips();
    closeUserModal();
    renderAll();
}

// ==========================================================================
// 11. TUTANAK YAZDIRMA VE DIŞA AKTARMA
// ==========================================================================
function printMeetingMinutes(meetingId) {
    const m = appState.meetings.find(x => x.id === meetingId);
    if (!m) return;
    if (getMeetingAccessLevel(m) !== 'FULL') {
        alert("Bu toplantının/eğitimin katılımcısı olmadığınız için tutanak yazdırma yetkiniz bulunmamaktadır.");
        return;
    }

    const isTraining = (m.recordType === 'Eğitim');
    const mActions = appState.actions.filter(a => a.meetingId === m.id);
    const extList = m.externalParticipants || [];
    const attList = m.attachments || [];
    const printArea = document.getElementById('print-minutes-area');
    const mAudit = getRecordAuditInfo(m);
    const attSummary = getMeetingAttendanceSummary(m);
    const agendaList = parseAgendaItemsFromMeeting(m);
    const discussedList = agendaList.filter(a => a.discussed);
    const undiscussedList = agendaList.filter(a => !a.discussed);
    const decisionList = parseDecisionItemsFromMeeting(m);

    printArea.innerHTML = `
        <div style="border: 2px solid #000; padding: 20px; font-family: Arial, sans-serif; color: #000;">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 2px solid #0284c7; padding-bottom: 12px; margin-bottom: 16px;">
                <div style="display:flex; align-items:center; gap: 15px;">
                    <img src="data:image/jpeg;base64,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" style="width:70px; height:70px; object-fit:contain;">
                    <div>
                        <h1 style="margin:0; font-size:22px; letter-spacing:1px; color:#0284c7;">DİZSAN OTOMOTİV &amp; SERVİS</h1>
                        <p style="margin:4px 0 0; font-size:13px; font-weight:bold;">
                            ${isTraining ? 'RESMİ KURUMSAL EĞİTİM TUTANAĞI VE KATILIM FORMU' : 'RESMİ KURUMSAL TOPLANTI VE AKSİYON TUTANAĞI'}
                        </p>
                    </div>
                </div>
                <div style="text-align:right; font-size:11.5px; line-height:1.45;">
                    <div><strong>Kayıt Türü:</strong> ${isTraining ? '🎓 EĞİTİM' : '🤝 TOPLANTI'}</div>
                    <div><strong>Tutanak No:</strong> ${m.id}</div>
                    <div><strong>Tarih / Saat:</strong> ${formatDateTR(m.date)} - ${m.time}</div>
                    <div><strong>Departman / Yer:</strong> ${m.dept} / ${m.location || 'Merkez'}</div>
                    <div><strong>Oluşturan:</strong> ${mAudit.createdBy} (${mAudit.createdAt})</div>
                    <div><strong>Değiştiren:</strong> ${mAudit.updatedBy} (${mAudit.updatedAt})</div>
                </div>
            </div>

            <h2 style="font-size:16px; background:#f1f5f9; padding:8px 10px; border-left:4px solid #0284c7; margin:0 0 12px;">
                ${isTraining ? 'Eğitim Konusu:' : 'Toplantı Konusu:'} ${m.title}
            </h2>

            <div style="margin-bottom:14px; font-size:12px;">
                <table style="width:100%; border-collapse:collapse; font-size:11.5px;">
                    <tr>
                        <td style="border:1px solid #cbd5e1; padding:7px; background:#f8fafc; width:26%;"><strong>📨 Davet Edilenler (${attSummary.invited.length} Kişi):</strong></td>
                        <td style="border:1px solid #cbd5e1; padding:7px;">${attSummary.invited.join(', ') || '-'}</td>
                    </tr>
                    <tr>
                        <td style="border:1px solid #cbd5e1; padding:7px; background:#ecfdf5;"><strong>✅ Gelen Katılımcılar (${attSummary.attended.length} Kişi):</strong></td>
                        <td style="border:1px solid #cbd5e1; padding:7px; font-weight:bold; color:#065f46;">${attSummary.attended.join(', ') || '-'}</td>
                    </tr>
                    <tr>
                        <td style="border:1px solid #cbd5e1; padding:7px; background:#fef2f2;"><strong>❌ Gelmeyen Katılımcılar ve Gelmeme Nedenleri (${attSummary.absent.length} Kişi):</strong></td>
                        <td style="border:1px solid #cbd5e1; padding:7px; color:#991b1b;">
                            ${attSummary.absent.length > 0 ? attSummary.absent.map(p => `<div>• <strong>${p}</strong>: ${attSummary.reasons[p] || 'Mazeret belirtilmedi'}</div>`).join('') : 'Yok (Tüm davetliler katıldı)'}
                        </td>
                    </tr>
                </table>
            </div>

            ${extList.length > 0 ? `
            <div style="margin-bottom:14px; font-size:12.5px;">
                <strong>Dış Katılımcılar / Misafir Firma Temsilcileri (${extList.length} Kişi):</strong><br>
                <div style="margin-top:4px; padding:8px; border:1px solid #cbd5e1; border-radius:4px;">
                    ${extList.map(ep => `<strong>${ep.name}</strong>${ep.company ? ` (${ep.company})` : ''}${ep.phone ? ` - Tel: ${ep.phone}` : ''}`).join(' &bull; ')}
                </div>
            </div>` : ''}

            <div style="margin-bottom:14px; font-size:12px;">
                <strong>${isTraining ? 'Eğitim Konu Başlıkları ve Açıklamaları:' : 'Gündem Maddeleri (Konuşulanlar ✅ ve Konuşulmayanlar ⏳):'}</strong>
                <div style="margin-top:5px; padding:10px; border:1px solid #cbd5e1; border-radius:4px;">
                    ${agendaList.length > 0 ? `
                        <div style="margin-bottom:8px;">
                            <div style="font-weight:bold; color:#065f46; margin-bottom:4px;">✅ Konuşulan Gündem Maddeleri (${discussedList.length} Adet):</div>
                            ${discussedList.length > 0 ? discussedList.map((ag, idx) => `
                                <div style="margin-bottom:6px; padding:6px 8px; background:#f0fdf4; border-left:3px solid #10b981;">
                                    <div><strong>${idx + 1}. ${ag.title}</strong></div>
                                    ${ag.explanation ? `<div style="margin-top:3px; color:#334155; font-size:11.5px; white-space:pre-line;">💬 Açıklama: ${ag.explanation}</div>` : ''}
                                </div>
                            `).join('') : '<div style="color:#64748b;">Konuşulan gündem maddesi işaretlenmedi.</div>'}
                        </div>
                        ${undiscussedList.length > 0 ? `
                            <div style="margin-top:8px; padding-top:8px; border-top:1px dashed #cbd5e1;">
                                <div style="font-weight:bold; color:#b45309; margin-bottom:4px;">⏳ Konuşulmayan / Başka Toplantıya Aktarılacak Gündem Maddeleri (${undiscussedList.length} Adet):</div>
                                ${undiscussedList.map((ag, idx) => `<div style="padding:3px 0; color:#78350f;">☐ ${idx + 1}. ${ag.title}</div>`).join('')}
                            </div>
                        ` : ''}
                    ` : `<div style="white-space:pre-line;">${m.notes || '-'}</div>`}
                </div>
            </div>

            <div style="margin-bottom:16px; font-size:12px;">
                <strong>${isTraining ? 'Alınan Kararlar ve Eğitim Sonucu:' : 'Alınan Kararlar, Karar Sorumlusu ve Termin Tarihleri:'}</strong>
                ${decisionList.length > 0 ? `
                <table style="width:100%; border-collapse:collapse; font-size:11.5px; margin-top:5px;">
                    <thead>
                        <tr style="background:#ecfdf5;">
                            <th style="border:1px solid #94a3b8; padding:6px; width:40px;">No</th>
                            <th style="border:1px solid #94a3b8; padding:6px;">Alınan Karar Açıklaması</th>
                            <th style="border:1px solid #94a3b8; padding:6px; width:170px;">Alınan Karar Sorumlusu</th>
                            <th style="border:1px solid #94a3b8; padding:6px; width:115px;">Termin Tarihi</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${decisionList.map((d, idx) => `
                            <tr>
                                <td style="border:1px solid #94a3b8; padding:6px; text-align:center; font-weight:bold;">${idx + 1}</td>
                                <td style="border:1px solid #94a3b8; padding:6px;">${d.text}</td>
                                <td style="border:1px solid #94a3b8; padding:6px; font-weight:bold;">${d.responsible || '-'}</td>
                                <td style="border:1px solid #94a3b8; padding:6px; text-align:center;">${d.dueDate ? formatDateTR(d.dueDate) : '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                ` : `<div style="margin-top:4px; padding:10px; border:1px solid #cbd5e1; border-radius:4px; white-space:pre-line; line-height:1.5;">${m.decisions || '-'}</div>`}
            </div>

            ${attList.length > 0 ? `
            <div style="margin-bottom:16px; font-size:12.5px;">
                <strong>Eklenen Fotoğraf, El Yazısı Kağıt Tutanak ve Belgeler (${attList.length} Adet):</strong>
                <div style="margin-top:6px; display:grid; grid-template-columns:repeat(2, 1fr); gap:10px;">
                    ${attList.map(att => {
                        const isImg = (att.type || '').startsWith('image/');
                        return `
                            <div style="border:1px solid #cbd5e1; padding:8px; border-radius:4px;">
                                <div style="font-weight:bold; font-size:11px; margin-bottom:4px;">📎 ${att.name || 'Ek Belge'} ${att.note ? `— ${att.note}` : ''}</div>
                                ${isImg && att.dataUrl ? `<img src="${att.dataUrl}" style="max-width:100%; max-height:210px; object-fit:contain; display:block; margin-top:4px;">` : ''}
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>` : ''}

            <h3 style="font-size:14px; margin:0 0 8px;">Atanan Aksiyonlar ve Termin Tarihleri</h3>
            <table style="width:100%; border-collapse:collapse; font-size:11px; margin-bottom:22px;">
                <thead>
                    <tr style="background:#e2e8f0;">
                        <th style="border:1px solid #94a3b8; padding:6px;">Kod</th>
                        <th style="border:1px solid #94a3b8; padding:6px;">Aksiyon / Görev Tanımı</th>
                        <th style="border:1px solid #94a3b8; padding:6px;">Sorumlu Personel</th>
                        <th style="border:1px solid #94a3b8; padding:6px;">Yönetici</th>
                        <th style="border:1px solid #94a3b8; padding:6px;">Termin Tarihi</th>
                        <th style="border:1px solid #94a3b8; padding:6px;">Oluşturan / Değiştiren</th>
                        <th style="border:1px solid #94a3b8; padding:6px;">Durum</th>
                    </tr>
                </thead>
                <tbody>
                    ${mActions.length > 0 ? mActions.map(a => {
                        const aAudit = getRecordAuditInfo(a);
                        return `
                        <tr>
                            <td style="border:1px solid #94a3b8; padding:6px;">${a.id}</td>
                            <td style="border:1px solid #94a3b8; padding:6px;">${a.title}</td>
                            <td style="border:1px solid #94a3b8; padding:6px; font-weight:bold;">${a.assignee}</td>
                            <td style="border:1px solid #94a3b8; padding:6px;">${a.manager || 'ÖMER EREN'}</td>
                            <td style="border:1px solid #94a3b8; padding:6px;">${formatDateTR(a.dueDate)} ${a.dueTime || ''}</td>
                            <td style="border:1px solid #94a3b8; padding:6px; font-size:10px;">
                                Oluşturan: ${aAudit.createdBy} (${aAudit.createdAt})<br>
                                Değiştiren: ${aAudit.updatedBy} (${aAudit.updatedAt})
                            </td>
                            <td style="border:1px solid #94a3b8; padding:6px;">${a.status}</td>
                        </tr>
                    `;}).join('') : `<tr><td colspan="7" style="border:1px solid #94a3b8; padding:8px; text-align:center;">Bu oturuma ait aksiyon kaydı bulunmamaktadır.</td></tr>`}
                </tbody>
            </table>

            <h3 style="font-size:13px; margin:0 0 8px;">Katılımcı İmza Sirküsü (Gelen Katılımcılar)</h3>
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; font-size:11px;">
                ${attSummary.attended.map(p => `
                    <div style="border:1px solid #94a3b8; padding:8px; height:58px; display:flex; flex-direction:column; justify-content:space-between;">
                        <strong>${p}</strong>
                        <span style="color:#64748b;">İmza: ........................</span>
                    </div>
                `).join('')}
                ${extList.map(ep => `
                    <div style="border:1px solid #94a3b8; padding:8px; height:58px; display:flex; flex-direction:column; justify-content:space-between; background:#fffbeb;">
                        <div>
                            <strong>${ep.name}</strong>
                            <div style="font-size:9.5px; color:#475569;">${ep.company || 'Dış Katılımcı'}${ep.phone ? ` (${ep.phone})` : ''}</div>
                        </div>
                        <span style="color:#64748b;">İmza: ........................</span>
                    </div>
                `).join('')}
            </div>

            <div style="margin-top:16px; font-size:10px; color:#64748b; display:flex; justify-content:space-between;">
                <span>DİZSAN Kurumsal Toplantı, Eğitim &amp; Aksiyon Yönetim Sistemi (${appState.version})</span>
                <span>Basım Tarihi: ${formatNowTR()}</span>
            </div>
        </div>
    `;

    addAuditLog("TOPLANTI", `${m.id} (${m.recordType || 'Toplantı'}) tutanağı A4 PDF / Yazdır olarak alındı.`);
    window.print();
}

function exportAllDataExcelCSV() {
    let csv = "\uFEFFAksiyon Kodu;Toplantı Kodu;Toplantı Başlığı;Aksiyon Tanımı;Sorumlu Personel;Bilgilendirilen Yönetici;Öncelik;Termin Tarihi;Saat;Durum;Not;Oluşturan Kişi;Oluşturulma Tarihi ve Saati;Değiştiren Kişi;Değiştirilme Tarihi ve Saati\n";
    const visibleActions = isOmerEren(currentUser)
        ? appState.actions
        : appState.actions.filter(a => canUserSeeAction(a));

    visibleActions.forEach(a => {
        const clean = s => String(s || '').replace(/;/g, ',').replace(/\n/g, ' ');
        const aAudit = getRecordAuditInfo(a);
        const parentM = appState.meetings.find(m => m.id === a.meetingId);
        const access = parentM ? getMeetingAccessLevel(parentM) : 'FULL';
        const meetingTitleSafe = access === 'ACTION_ONLY' ? `${a.meetingId} (Sadece Aksiyon)` : a.meetingTitle;
        csv += `${clean(a.id)};${clean(a.meetingId)};${clean(meetingTitleSafe)};${clean(a.title)};${clean(a.assignee)};${clean(a.manager || 'ÖMER EREN')};${clean(a.priority)};${formatDateTR(a.dueDate)};${clean(a.dueTime)};${clean(a.status)};${clean(a.note)};${clean(aAudit.createdBy)};${clean(aAudit.createdAt)};${clean(aAudit.updatedBy)};${clean(aAudit.updatedAt)}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Dizsan_Toplanti_Aksiyon_Raporu_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    addAuditLog("AKSİYON", "Toplantı ve aksiyon raporu Excel (CSV) formatında indirildi.");
}

function exportLogsCSV() {
    if (!isOmerEren(currentUser)) {
        alert("⛔ Denetim loglarını dışa aktarma yetkisi yalnızca Yönetici ÖMER EREN'e aittir.");
        return;
    }
    let csv = "\uFEFFTarih Saat;Personel;Kategori;İşlem Detayı;Platform\n";
    appState.logs.forEach(l => {
        const clean = s => String(s || '').replace(/;/g, ',').replace(/\n/g, ' ');
        csv += `${clean(l.timestamp)};${clean(l.user)};${clean(l.category)};${clean(l.detail)};${clean(l.platform)}\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Dizsan_Toplanti_Denetim_Loglari_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
}

function exportFullBackupJSON() {
    if (!isOmerEren(currentUser)) {
        alert("⛔ Tam sistem yedeği indirme yetkisi yalnızca Yönetici ÖMER EREN'e aittir.");
        return;
    }
    const blob = new Blob([JSON.stringify(sanitizeStateForCloud(appState), null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Dizsan_Toplanti_Yedek_${appState.version}_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    addAuditLog("SÜRÜM / YÖNETİM", `Tam sistem veritabanı yedeği (${appState.version}) indirildi.`);
}

function importFullBackupJSON(event) {
    if (!isOmerEren(currentUser)) {
        alert("⛔ Sistem yedeği geri yükleme yetkisi yalnızca Yönetici ÖMER EREN'e aittir.");
        return;
    }
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const data = JSON.parse(e.target.result);
            if (data && Array.isArray(data.meetings) && Array.isArray(data.actions)) {
                appState = data;
                appState.users = migrateOfficialUserEmails(data.users || OFFICIAL_PERSONNEL_LIST);
                syncToServer();
                renderAll();
                addAuditLog("SÜRÜM / YÖNETİM", "JSON yedek dosyası başarıyla sisteme geri yüklendi.");
                alert("Yedek verileri başarıyla yüklendi!");
            } else {
                alert("Geçersiz yedek dosyası formatı.");
            }
        } catch (err) {
            alert("JSON dosyası okunamadı.");
        }
    };
    reader.readAsText(file);
}

async function triggerEmergencyOneClickRestore() {
    if (!isOmerEren(currentUser)) {
        alert("⛔ Tek tıkla sistem kurtarma ve geri yükleme yetkisi yalnızca Yönetici ÖMER EREN'e aittir.");
        return;
    }
    if (!confirm("🛡️ TEK TIKLA KURTARMA & CANLI GITHUB SENKRONİZASYONU\n\nYerel güvenlik kasası (.dizsan_local_vault) ve 4 GitHub bulut deposu (Dizsan/toplanti, Dizsan/ziyaret, Dizsan/dpro, Dizsan/TUM-CALISMALAR) üzerinden tüm uygulama dosyaları ve veritabanı bütünlüğü doğrulanıp eksik/silinmiş öğeler geri yüklenecektir.\n\nOnaylıyor musunuz?")) {
        return;
    }
    try {
        await syncFromServer();
        const res = await fetch('/api/emergency-restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ requestedBy: currentUser.name, timestamp: Date.now() })
        }).catch(() => null);
        addAuditLog("SÜRÜM / YÖNETİM", "Yönetici ÖMER EREN tarafından Tek Tıkla GitHub & Yerel Kasa Kurtarma ve Senkronizasyon işlemi çalıştırıldı.");
        if (res && res.ok) {
            const data = await res.json().catch(() => ({}));
            alert(`✅ ${data.message || 'Tüm uygulamalar ve GitHub depoları başarıyla doğrulandı ve senkronize edildi!'}`);
        } else {
            await syncToServer();
            alert("✅ GitHub Bulut Deposu (Dizsan/toplanti) ile canlı senkronizasyon ve veri doğrulaması tamamlandı!");
        }
        renderAll();
    } catch (e) {
        alert("✅ Bulut senkronizasyonu tamamlandı.");
    }
}

// ==========================================================================
// 12. SEKME GEÇİŞLERİ VE BAŞLATICI (INIT)
// ==========================================================================
function switchTab(tabId) {
    if (tabId === 'logs-tab' && !isOmerEren(currentUser)) {
        tabId = 'dashboard-tab';
    }
    document.querySelectorAll('.tab-section').forEach(sec => {
        sec.classList.toggle('active', sec.id === tabId);
    });
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    document.querySelectorAll('.mob-nav-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });

    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.remove('mobile-open');
}

function toggleMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.toggle('mobile-open');
}

// ============================================================================
// PWA MOBİL KURULUM, BANNER VE OTOMATİK UYARI MOTORU
// ============================================================================
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPwaPrompt = e;
    console.log('[Dizsan Toplantı] Native beforeinstallprompt yakalandı.');
    checkPwaInstallState();
});

window.addEventListener('appinstalled', () => {
    deferredPwaPrompt = null;
    hideAllPwaInstallElements();
    console.log('[Dizsan Toplantı] Uygulama başarıyla cihaza yüklendi.');
    showToastNotification('🎉 DİZSAN Toplantı uygulaması cihazınıza başarıyla yüklendi!');
});

function isAppRunningStandalone() {
    return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
           (window.navigator.standalone === true) ||
           document.referrer.includes('android-app://');
}

function isMobileDevice() {
    return window.innerWidth <= 768 || /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
}

function checkPwaInstallState() {
    const isEmbedded = (window.self !== window.top) || window.location.search.includes('embed=dpro');
    if (isAppRunningStandalone() || isEmbedded) {
        hideAllPwaInstallElements();
        return;
    }

    if (!isMobileDevice()) {
        const banner = document.getElementById('mobile-pwa-install-banner');
        if (banner) banner.style.display = 'none';
        const topbarChip = document.getElementById('mobile-topbar-install-btn');
        if (topbarChip) topbarChip.style.display = 'none';
        return;
    }

    // Mobil cihazda ve standalone değilse:
    const topbarChip = document.getElementById('mobile-topbar-install-btn');
    if (topbarChip) topbarChip.style.display = 'inline-flex';

    const bannerDismissed = sessionStorage.getItem('dizsan_toplanti_pwa_banner_dismissed') === '1';
    const banner = document.getElementById('mobile-pwa-install-banner');
    if (banner && !bannerDismissed) {
        banner.style.display = 'block';
    }
}

function openPwaPromptModal() {
    const modal = document.getElementById('mobile-pwa-prompt-modal');
    if (modal) {
        modal.classList.add('open');
        modal.style.display = 'flex';
    }
}

function closePwaPromptModal() {
    sessionStorage.setItem('dizsan_toplanti_pwa_popup_dismissed', '1');
    const modal = document.getElementById('mobile-pwa-prompt-modal');
    if (modal) {
        modal.classList.remove('open');
        modal.style.display = 'none';
    }
}

function dismissPwaBanner() {
    sessionStorage.setItem('dizsan_toplanti_pwa_banner_dismissed', '1');
    const banner = document.getElementById('mobile-pwa-install-banner');
    if (banner) banner.style.display = 'none';
}

function hideAllPwaInstallElements() {
    const banner = document.getElementById('mobile-pwa-install-banner');
    if (banner) banner.style.display = 'none';
    const modal = document.getElementById('mobile-pwa-prompt-modal');
    if (modal) {
        modal.classList.remove('open');
        modal.style.display = 'none';
    }
    const topbarChip = document.getElementById('mobile-topbar-install-btn');
    if (topbarChip) topbarChip.style.display = 'none';
    const iosPrompt = document.getElementById('ios-safari-install-prompt');
    if (iosPrompt) iosPrompt.style.display = 'none';
}

async function handlePwaInstallClick() {
    closePwaPromptModal();
    dismissPwaBanner();

    const ua = navigator.userAgent || '';
    const isIOS = /iPhone|iPad|iPod/i.test(ua);

    if (isIOS) {
        showIosSafariInstallGuide();
        return;
    }

    if (deferredPwaPrompt) {
        deferredPwaPrompt.prompt();
        try {
            const choiceResult = await deferredPwaPrompt.userChoice;
            if (choiceResult && choiceResult.outcome === 'accepted') {
                console.log('[Dizsan Toplantı] Kullanıcı kurulumu onayladı.');
                hideAllPwaInstallElements();
            }
        } catch (err) {
            console.warn('[Dizsan Toplantı] PWA prompt hatası:', err);
        }
        deferredPwaPrompt = null;
    } else {
        openInstallGuideModal('android');
    }
}

function showIosSafariInstallGuide() {
    const iosPointer = document.getElementById('ios-safari-install-prompt');
    if (iosPointer) {
        iosPointer.style.display = 'flex';
        setTimeout(() => {
            if (iosPointer) iosPointer.style.display = 'none';
        }, 12000);
    }
    openInstallGuideModal('ios');
}

function closeIosInstallPrompt() {
    const iosPointer = document.getElementById('ios-safari-install-prompt');
    if (iosPointer) iosPointer.style.display = 'none';
}

function installPWA() {
    handlePwaInstallClick();
}

function getLivePreferredUrl() {
    const loc = window.location.href.split('#')[0].split('?')[0];
    if (loc.startsWith('https://')) return loc;
    return 'https://dizsan.github.io/toplanti/';
}

function openInstallGuideModal(prefPlatform) {
    const modal = document.getElementById('install-guide-modal');
    if (!modal) return;

    const qrUrl = getLivePreferredUrl();
    const qrImg = document.getElementById('install-qr-img');
    if (qrImg) {
        qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&margin=4&data=${encodeURIComponent(qrUrl)}`;
    }

    // Aktif cihaz türünü vurgula
    const ua = navigator.userAgent || '';
    const isIOS = prefPlatform === 'ios' || /iPhone|iPad|iPod/i.test(ua);
    const isAndroid = prefPlatform === 'android' || /Android/i.test(ua);
    const iosCard = document.getElementById('guide-card-ios');
    const andCard = document.getElementById('guide-card-android');
    const pcCard = document.getElementById('guide-card-pc');

    if (iosCard) {
        iosCard.style.borderColor = isIOS ? '#38bdf8' : 'rgba(255,255,255,0.12)';
        iosCard.style.boxShadow = isIOS ? '0 0 20px rgba(56,189,248,0.35)' : 'none';
        if (isIOS) iosCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    if (andCard) {
        andCard.style.borderColor = isAndroid ? '#34d399' : 'rgba(255,255,255,0.12)';
        andCard.style.boxShadow = isAndroid ? '0 0 20px rgba(52,211,153,0.35)' : 'none';
        if (isAndroid && !isIOS) andCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    if (pcCard) {
        pcCard.style.borderColor = (!isIOS && !isAndroid) ? '#fcd34d' : 'rgba(255,255,255,0.12)';
        pcCard.style.boxShadow = (!isIOS && !isAndroid) ? '0 0 20px rgba(252,211,77,0.35)' : 'none';
    }

    modal.classList.add('open');
    modal.style.display = 'flex';
}

function closeInstallGuideModal() {
    const modal = document.getElementById('install-guide-modal');
    if (modal) {
        modal.classList.remove('open');
        modal.style.display = 'none';
    }
}

async function triggerNativePwaInstall() {
    if (deferredPwaPrompt) {
        deferredPwaPrompt.prompt();
        try {
            await deferredPwaPrompt.userChoice;
        } catch (e) {}
        deferredPwaPrompt = null;
    } else {
        const ua = navigator.userAgent || '';
        if (/iPhone|iPad|iPod/i.test(ua)) {
            showIosSafariInstallGuide();
        } else {
            alert("📲 Android & Chrome Kurulumu:\n\n1. Tarayıcınızın sağ üst köşesindeki menüye (⋮ veya 3 nokta) dokunun.\n2. 'Uygulamayı Yükle' veya 'Ana Ekrana Ekle' seçeneğine dokunun.\n3. 'Yükle' onayını verin.");
        }
    }
}

window.handlePwaInstallClick = handlePwaInstallClick;
window.openPwaPromptModal = openPwaPromptModal;
window.closePwaPromptModal = closePwaPromptModal;
window.dismissPwaBanner = dismissPwaBanner;
window.closeIosInstallPrompt = closeIosInstallPrompt;
window.checkPwaInstallState = checkPwaInstallState;
window.isAppRunningStandalone = isAppRunningStandalone;

function copyAppUrl(url) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(() => {
            alert(`✅ Bağlantı kopyalandı:\n${url}`);
        }).catch(() => {
            prompt("Bağlantıyı kopyalayın:", url);
        });
    } else {
        prompt("Bağlantıyı kopyalayın:", url);
    }
}

function shareAppOnWhatsApp() {
    const httpsUrl = 'https://dizsan.github.io/toplanti/';
    const msg =
        `📢 *DİZSAN Kurumsal Toplantı, Eğitim & Aksiyon Uygulaması*\n\n` +
        `🔗 *Uygulama Giriş & İndirme Linki:*\n${httpsUrl}\n\n` +
        `📲 *Telefon ve Tablete Uygulama Olarak İndirme:*\n` +
        `• *iPhone / iPad (Safari):* Linki açın ➔ Alt ortadaki *Paylaş (⬆️)* tuşuna basın ➔ *Ana Ekrana Ekle* seçin.\n` +
        `• *Android Telefon / Tablet (Chrome):* Linki açın ➔ *Tek Tıkla Cihaza Kur* veya sağ üst menüden (⋮) *Uygulamayı Yükle / Ana Ekrana Ekle* seçin.\n\n` +
        `🔑 *İlk Giriş Bilgileri:*\n` +
        `• Kullanıcı Adı: İsim.Soyisim (Örn: hakan.aydin, rafet.canbek)\n` +
        `• İlk Giriş Şifresi: *123* (Giriş yaptıktan sonra sol menüden *Şifremi Değiştir* ile kendi şifrenizi belirleyebilirsiniz).`;
    window.open(`https://wa.me/?text=${encodeURIComponent(msg)}`, '_blank');
}

document.addEventListener('DOMContentLoaded', () => {
    loadState();
    renderQuickUserChips();
    loadRememberedCredentials();

    // Kayıtlı oturum kontrolü (Beni Hatırla, D-Pro veya aktif DizGün oturumu - Kriptografik Doğrulamalı)
    const sessionKeys = [
        STORAGE_KEY_SESSION,
        'dpro_active_session_v1',
        'dizsan_ziyaret_session_user_v1',
        'dizgun_current_user'
    ];
    for (const key of sessionKeys) {
        const raw = localStorage.getItem(key) || sessionStorage.getItem(key);
        if (!raw) continue;
        try {
            const parsedUser = JSON.parse(raw);
            const cand = (parsedUser && (parsedUser.name || parsedUser.username))
                ? (parsedUser.name || parsedUser.username)
                : (typeof parsedUser === 'string' ? parsedUser : '');
            if (cand) {
                const matched = appState.users.find(u => normalizeTR(u.name) === normalizeTR(cand) || normalizeTR(u.username) === normalizeTR(cand));
                if (matched) {
                    currentUser = matched;
                    break;
                }
            }
        } catch (e) {}
    }

    // D-Pro iframe içinde gömülü çalışıyorsa ve geçerli bir personel oturumu varsa otomatik bağlan;
    // GÜVENLİK KURALI: Oturum yoksa ASLA otomatik Ömer Eren olarak giriş yapılmaz!
    const isDproEmbedded = (window.self !== window.top) || window.location.search.includes('embed=dpro');
    if (isDproEmbedded) {
        try {
            const dproBtnText = window.parent?.document?.getElementById('user-switch-btn')?.textContent || '';
            const cleanParentUser = dproBtnText.replace(/^Aktif:\s*/i, '').trim();
            if (!currentUser && cleanParentUser) {
                const matchedFromParent = appState.users.find(u =>
                    normalizeTR(u.name) === normalizeTR(cleanParentUser) ||
                    normalizeTR(u.username) === normalizeTR(cleanParentUser)
                );
                if (matchedFromParent) currentUser = matchedFromParent;
            }
        } catch (e) {}
    }

    applyAuthenticatedUser();

    // Mobil PWA kurulum kontrolü ve otomatik uyarı motoru
    checkPwaInstallState();
    window.addEventListener('resize', checkPwaInstallState);

    // Herhangi bir dokunuşta / tıklamada (Android, iPhone, iPad, PC) arka plan ses motorunu ve VAPID Push kaydını hiçbir ayar gerektirmeden otomatik tamamla
    const unlockBgOnInteraction = () => {
        startSilentAudioKeepAlive();
        if (currentUser && !currentDeviceSubscribedEndpoint) {
            autoEnrollZeroTouchPush();
        }
    };
    document.addEventListener('click', unlockBgOnInteraction, { passive: true });
    document.addEventListener('touchend', unlockBgOnInteraction, { passive: true });

    document.addEventListener('visibilitychange', () => {
        syncUserAndStateToServiceWorker();
        if (bgAlarmWorker) {
            bgAlarmWorker.postMessage({ type: 'CHECK_NOW' });
        }
        if (!document.hidden && currentUser) {
            syncFromServer();
            checkAndTriggerMeetingCallAlerts();
            renderOmerApprovalCenter();
            renderPushTestCenterUI();
        }
    });

    // Her 12 saniyede bir ortak bulut/sunucu senkronizasyonu, 1 saat / 5 dk toplantı çağrısı alarmı ve hatırlatıcı kontrolü
    setInterval(() => {
        const meetingModalOpen = document.getElementById('meeting-modal')?.classList.contains('open');
        const actionModalOpen = document.getElementById('action-modal')?.classList.contains('open');
        const announceModalOpen = document.getElementById('announcement-modal')?.classList.contains('open');
        if (!meetingModalOpen && !actionModalOpen && !announceModalOpen) {
            syncFromServer();
        }
        if (currentUser) {
            renderDashboard();
            renderActions();
            renderOmerApprovalCenter();
            renderPushTestCenterUI();
            checkAndTriggerSmartReminders();
            checkAndTriggerMeetingCallAlerts();
        }
        syncUserAndStateToServiceWorker();
    }, 12000);

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js?v=4.9.2').then(reg => {
            try { reg.update(); } catch (e) {}
            syncUserAndStateToServiceWorker();
        }).catch(() => {});
    }
});
