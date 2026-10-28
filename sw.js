const CACHE_NAME = 'dizsan-toplanti-v5.0.3';
const ASSETS = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './dizsan-back-navigation.js',
  './alarm-worker.js',
  './auto-date-helper.js',
  './dizsan_logo.jpg',
  './apple-touch-icon.png',
  './icon-192.png',
  './icon-512.png',
  './manifest.json'
];

const DB_NAME = 'dizsan_bg_db';
const STORE_NAME = 'bg_store';
const CLOUD_KEY_CODES = [106, 107, 115, 98, 91, 123, 91, 82, 116, 68, 73, 89, 125, 119, 57, 84, 112, 75, 86, 86, 109, 86, 112, 72, 103, 80, 116, 87, 117, 111, 113, 57, 125, 80, 53, 105, 76, 60, 120, 79];
const CLOUD_API_URL = 'https://api.github.com/repos/Dizsan/toplanti/contents/shared_state.json';

let swPollTimer = null;
let lastSwCheckTime = 0;

function getCloudAuthToken() {
  return CLOUD_KEY_CODES.map((c) => String.fromCharCode(c - 3)).join('');
}

function decodeUTF8Base64(b64) {
  return decodeURIComponent(escape(atob(b64.replace(/\s/g, ''))));
}

function openBgDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(key) {
  try {
    const db = await openBgDB();
    return await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    });
  } catch (e) {
    return null;
  }
}

async function dbSet(key, val) {
  try {
    const db = await openBgDB();
    return await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put(val, key);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
    });
  } catch (e) {
    return false;
  }
}

function normalizeTR(str) {
  if (!str) return '';
  return String(str)
    .trim()
    .toLocaleLowerCase('tr-TR')
    .replace(/ğ/g, 'g')
    .replace(/ü/g, 'u')
    .replace(/ş/g, 's')
    .replace(/ı/g, 'i')
    .replace(/ö/g, 'o')
    .replace(/ç/g, 'c')
    .replace(/\s+/g, ' ');
}

function getMinutesDiff(dateStr, timeStr) {
  if (!dateStr || !timeStr) return null;
  let iso = String(dateStr).trim();
  if (/^\d{2}\.\d{2}\.\d{4}$/.test(iso)) {
    const [d, m, y] = iso.split('.');
    iso = `${y}-${m}-${d}`;
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) return null;
  const [y, mo, d] = iso.split('-').map(Number);
  const parts = String(timeStr).trim().split(':').map(Number);
  const hh = parts[0];
  const mm = parts[1] || 0;
  if (!y || !mo || !d || isNaN(hh) || isNaN(mm)) return null;
  const target = new Date(y, mo - 1, d, hh, mm, 0, 0);
  return (target.getTime() - Date.now()) / 60000;
}

function formatDateTR(val) {
  if (!val) return '-';
  const str = String(val).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(str)) {
    const [y, m, d] = str.split('-');
    return `${d}.${m}.${y}`;
  }
  return str;
}

async function showSystemNotification(title, body, tag, alertType = 'INVITE', url = './') {
  const notifiedMap = (await dbGet('notifiedMap')) || {};
  if (tag && notifiedMap[tag]) return false;
  if (tag) {
    notifiedMap[tag] = Date.now();
    await dbSet('notifiedMap', notifiedMap);
  }

  const vibratePattern =
    alertType === 'RED_5M'
      ? [700, 150, 700, 150, 900, 150, 900]
      : alertType === 'YELLOW_1H' || alertType === 'APPROVAL'
      ? [500, 150, 500, 150, 600]
      : [350, 120, 350];

  try {
    await self.registration.showNotification(title, {
      body,
      icon: './icon-192.png',
      badge: './icon-192.png',
      tag: tag || 'dizsan-alert-' + Date.now(),
      renotify: true,
      requireInteraction: true,
      silent: false,
      vibrate: vibratePattern,
      data: { url, alertType, timestamp: Date.now() },
      actions: [
        { action: 'open', title: '👉 Uygulamayı Aç' }
      ]
    });

    const allClients = await self.clients.matchAll({ includeUncontrolled: true, type: 'window' });
    for (const client of allClients) {
      client.postMessage({
        type: 'SW_ALARM_TRIGGERED',
        alertType,
        title,
        body,
        tag
      });
    }
    return true;
  } catch (err) {
    return false;
  }
}

async function fetchRealTimeCloudState() {
  try {
    const token = getCloudAuthToken();
    const res = await fetch(`${CLOUD_API_URL}?t=${Date.now()}`, {
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      },
      cache: 'no-store'
    });
    if (res.ok) {
      const fileObj = await res.json();
      if (fileObj && fileObj.content) {
        return JSON.parse(decodeUTF8Base64(fileObj.content));
      }
    }
  } catch (e) {}

  try {
    const res2 = await fetch(`./shared_state.json?t=${Date.now()}`, { cache: 'no-store' });
    if (res2.ok) return await res2.json();
  } catch (e) {}
  return null;
}

async function checkRemoteStateInBackground(forceState = null) {
  const now = Date.now();
  if (!forceState && now - lastSwCheckTime < 6000) return;
  lastSwCheckTime = now;

  try {
    const user = await dbGet('currentUser');
    if (!user || !user.name) return;

    const myNameNorm = normalizeTR(user.name);
    const isOmer = myNameNorm === 'omer eren' || normalizeTR(user.username) === 'omer' || normalizeTR(user.username) === 'omer.eren';

    const state = forceState || (await fetchRealTimeCloudState());
    if (!state) return;

    const deletedSet = new Set(Array.isArray(state.deletedIds) ? state.deletedIds : []);

    // 1. Toplantı Çağrıları, 1 Saat Kala Sarı, 5 Dakika Kala Kırmızı ve Yönetici Onayı Bildirimleri
    const meetings = Array.isArray(state.meetings) ? state.meetings : [];
    for (const m of meetings) {
      if (!m || !m.id || deletedSet.has(m.id)) continue;
      const isInvited = (m.participants || []).some((p) => normalizeTR(p) === myNameNorm) || isOmer;
      const recLabel = m.recordType === 'Eğitim' ? 'Eğitim' : 'Toplantı';
      const isEditedRecord = Boolean(m.updatedBy || m.updatedAt);

      if (isInvited && !isEditedRecord) {
        const diffMins = getMinutesDiff(m.date, m.time);
        if (diffMins !== null) {
          if (diffMins >= -15 && diffMins <= 5) {
            const tag = `alert_red5m_${m.id}_${myNameNorm}_${m.date}_${m.time}`;
            await showSystemNotification(
              `🟥 KIRMIZI UYARI: ${recLabel} 5 Dakika İçinde Başlıyor!`,
              `"${m.title}" saat ${m.time}'da (${m.location || 'Toplantı Salonu'}) başlıyor! Lütfen toplantı yerine geçiniz.`,
              tag,
              'RED_5M'
            );
          } else if (diffMins > 5 && diffMins <= 60) {
            const minsLeft = Math.ceil(diffMins);
            const tag = `alert_yellow1h_${m.id}_${myNameNorm}_${m.date}_${m.time}`;
            await showSystemNotification(
              `🟨 SARI UYARI: ${recLabel} Saatine 1 Saatten Az (${minsLeft} Dk) Kaldı!`,
              `"${m.title}" bugün saat ${m.time}'da (${m.location || 'Toplantı Salonu'}) başlayacak.`,
              tag,
              'YELLOW_1H'
            );
          } else if (diffMins > 60 && diffMins <= 60 * 24 * 14) {
            const tag = `alert_invite_${m.id}_${myNameNorm}`;
            await showSystemNotification(
              `📢 Yeni ${recLabel} Çağrısı: ${m.title}`,
              `📅 Tarih: ${formatDateTR(m.date)} Saat: ${m.time} • Yer: ${m.location || 'Toplantı Salonu'} (Davetlisiniz)`,
              tag,
              'INVITE'
            );
          }
        }
      }

      // Ömer Eren için yeni toplantı yönetici onayı bildirimi (omerApprovedStamp yoksa onay bekliyor demektir)
      if (isOmer && m.omerApprovedStamp !== true) {
        const appTag = `omer_approve_meeting_${m.id}`;
        await showSystemNotification(
          `🛡️ Yönetici Onayı Bekleyen ${recLabel}: ${m.id}`,
          `${m.createdBy || 'Personel'} tarafından kaydedilen "${m.title}" yönetici onayınızı bekliyor.`,
          appTag,
          'APPROVAL'
        );
      }
    }

    // 2. Kurumsal Duyurular
    const announcements = Array.isArray(state.announcements) ? state.announcements : [];
    for (const ann of announcements) {
      const isTarget = (ann.participants || []).some((p) => normalizeTR(p) === myNameNorm) || isOmer;
      if (!isTarget) continue;
      const dismissed = Array.isArray(ann.dismissedBy) ? ann.dismissedBy : [];
      if (dismissed.some((u) => normalizeTR(u) === myNameNorm)) continue;

      const tag = `alert_ann_${ann.id}_${myNameNorm}`;
      await showSystemNotification(
        `📣 DİZSAN Duyuru: ${ann.title}`,
        ann.message,
        tag,
        'INVITE'
      );
    }

    // 3. Ömer Eren için Silme Onay Talepleri Bildirimi (Düzenleme/Değiştirme taleplerinde bildirim kapalı)
    if (isOmer && Array.isArray(state.approvalRequests)) {
      for (const req of state.approvalRequests) {
        if (req.status !== 'PENDING' || req.type === 'EDIT_MEETING') continue;
        const reqTag = `omer_req_${req.id}`;
        const typeLabel = req.type === 'DELETE_MEETING' ? 'Silme Onayı' : 'Değiştirme (Düzenleme) Onayı';
        await showSystemNotification(
          `🛡️ Ömer Eren Onayı Bekleniyor (${typeLabel})`,
          `${req.requestedBy} personeli "${req.meetingTitle}" (${req.meetingId}) kaydı için ${typeLabel.toLowerCase()} talep etti.`,
          reqTag,
          'APPROVAL'
        );
      }
    }
  } catch (err) {}
}

function ensureSwLoop() {
  if (swPollTimer) clearInterval(swPollTimer);
  swPollTimer = setInterval(() => {
    checkRemoteStateInBackground();
  }, 10000);
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.all(
        ASSETS.map((url) =>
          fetch(new Request(url, { cache: 'reload' }))
            .then((res) => (res && res.ok ? cache.put(url, res) : null))
            .catch(() => {})
        )
      )
    )
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)));
      await self.clients.claim();
      const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const client of clientList) {
        try {
          client.postMessage({ type: 'FORCE_RELOAD_VERSION', version: CACHE_NAME });
        } catch (e) {}
      }
      ensureSwLoop();
    })()
  );
});

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'SYNC_USER_TO_SW') {
    dbSet('currentUser', data.user).then(() => {
      ensureSwLoop();
      checkRemoteStateInBackground(data.state || null);
    });
  } else if (data.type === 'TRIGGER_OS_NOTIFICATION') {
    showSystemNotification(data.title, data.body, data.tag, data.alertType || 'INVITE');
  } else if (data.type === 'CHECK_STATE_NOW') {
    ensureSwLoop();
    checkRemoteStateInBackground(data.state || null);
  }
});

self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'dizsan-periodic-check') {
    event.waitUntil(checkRemoteStateInBackground());
  }
});

self.addEventListener('sync', (event) => {
  if (event.tag === 'dizsan-sync-check') {
    event.waitUntil(checkRemoteStateInBackground());
  }
});

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (e) {}
  event.waitUntil(
    showSystemNotification(
      payload.title || '🔔 DİZSAN Toplantı & Çağrı Bildirimi',
      payload.body || 'Yeni bir toplantı çağrısı veya yönetici onay bildirimi var.',
      payload.tag || 'push-' + Date.now(),
      payload.alertType || 'YELLOW_1H'
    )
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) ? event.notification.data.url : './';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) {
          client.postMessage({ type: 'NOTIFICATION_CLICKED', data: event.notification.data });
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});

self.addEventListener('fetch', (event) => {
  const url = event.request.url;
  if (Date.now() - lastSwCheckTime > 12000) {
    checkRemoteStateInBackground();
  }
  if (
    event.request.method !== 'GET' ||
    url.includes('api.php') || url.includes("version.json") ||
    url.includes('/api/') ||
    url.includes('api.github.com') ||
    url.includes('shared_state.json')
  ) {
    return;
  }

  event.respondWith(
    fetch(event.request, { cache: 'no-store' })
      .then((response) => {
        if (response && response.status === 200) {
          const cloned = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, cloned));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
