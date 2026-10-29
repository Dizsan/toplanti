<?php
/**
 * DİZSAN KURUMSAL TOPLANTI, AKSİYON & DENETİM SİSTEMİ - PHP BACKEND API (v1.8.4)
 * Ortak Veri Senkronizasyonu + Zorunlu Kurumsal E-Posta Şifre Sıfırlama Bağlantısı (Linki) Gönderimi
 */
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$dataFile = __DIR__ . '/shared_state.json';
$action = isset($_GET['action']) ? $_GET['action'] : 'state';

if (($action === 'send_reset_link' || $action === 'send_reset_code') && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input');
    $payload = json_decode($rawInput, true);
    $email = isset($payload['email']) ? strtolower(trim($payload['email'])) : '';
    $resetLink = isset($payload['resetLink']) ? trim($payload['resetLink']) : '';
    $name = isset($payload['name']) ? trim($payload['name']) : 'Personel';

    if ($email && substr($email, -14) === '@dizsan.com.tr' && $resetLink) {
        $subject = "=?UTF-8?B?" . base64_encode("DİZSAN Toplantı Sistemi - Şifre Yenileme Bağlantısı") . "?=";
        $message = "Sayın $name,\n\nDİZSAN Kurumsal Toplantı ve Aksiyon Yönetim Sistemi şifre sıfırlama talebiniz alınmıştır.\n\nYeni şifrenizi belirlemek için aşağıdaki tek kullanımlık güvenli bağlantıya tıklayınız (15 dakika geçerlidir):\n\n$resetLink\n\nBu talebi siz oluşturmadıysanız bu e-postayı dikkate almayınız.\n\nİyi çalışmalar dileriz,\nDİZSAN Otomotiv & Servis";
        $headers = "From: bilgi@dizsan.com.tr\r\n" .
                   "Reply-To: bilgi@dizsan.com.tr\r\n" .
                   "Content-Type: text/plain; charset=UTF-8\r\n";
        $mailSent = @mail($email, $subject, $message, $headers);
        echo json_encode([
            'status' => 'ok',
            'mail_sent' => (bool)$mailSent,
            'email' => $email
        ], JSON_UNESCAPED_UNICODE);
    } else {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz kurumsal e-posta (@dizsan.com.tr zorunludur) veya sıfırlama bağlantısı eksik']);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (file_exists($dataFile)) {
        echo file_get_contents($dataFile);
    } else {
        echo json_encode(['status' => 'empty', 'data' => null]);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input');
    $decoded = json_decode($rawInput, true);
    if ($decoded !== null && is_array($decoded)) {
        if (isset($decoded['users']) && is_array($decoded['users'])) {
            foreach ($decoded['users'] as &$u) {
                if (is_array($u) && isset($u['password'])) {
                    unset($u['password']);
                }
            }
            unset($u);
        }
        $attDir = __DIR__ . '/attachments';
        if (!is_dir($attDir)) {
            @mkdir($attDir, 0775, true);
        }
        if (isset($decoded['meetings']) && is_array($decoded['meetings'])) {
            foreach ($decoded['meetings'] as &$m) {
                if (is_array($m) && isset($m['attachments']) && is_array($m['attachments'])) {
                    foreach ($m['attachments'] as &$att) {
                        if (is_array($att) && !empty($att['dataUrl']) && strpos($att['dataUrl'], 'data:') === 0) {
                            $commaPos = strpos($att['dataUrl'], ',');
                            if ($commaPos !== false) {
                                $b64 = preg_replace('/\s+/', '', substr($att['dataUrl'], $commaPos + 1));
                                $bin = base64_decode($b64, true);
                                if ($bin !== false && strlen($bin) > 0) {
                                    $rawId = isset($att['id']) && $att['id'] !== '' ? (string)$att['id'] : (string)time();
                                    $safeId = preg_replace('/[^A-Za-z0-9_-]/', '_', $rawId);
                                    $mime = strtolower(isset($att['type']) ? (string)$att['type'] : '');
                                    $nameLower = strtolower(isset($att['name']) ? (string)$att['name'] : '');
                                    $ext = '.bin';
                                    if (strpos($mime, 'pdf') !== false || substr($nameLower, -4) === '.pdf') {
                                        $ext = '.pdf';
                                    } elseif (strpos($mime, 'png') !== false || substr($nameLower, -4) === '.png') {
                                        $ext = '.png';
                                    } elseif (strpos($mime, 'jpeg') !== false || strpos($mime, 'jpg') !== false || substr($nameLower, -4) === '.jpg' || substr($nameLower, -5) === '.jpeg') {
                                        $ext = '.jpg';
                                    } elseif (strpos($mime, 'webp') !== false || substr($nameLower, -5) === '.webp') {
                                        $ext = '.webp';
                                    }
                                    $relPath = 'attachments/' . $safeId . $ext;
                                    $absPath = $attDir . '/' . $safeId . $ext;
                                    if (@file_put_contents($absPath, $bin) !== false) {
                                        $att['fileUrl'] = $relPath;
                                        $att['dataUrl'] = '';
                                    }
                                }
                            }
                        }
                    }
                    unset($att);
                }
            }
            unset($m);
        }
        $existing = [];
        if (file_exists($dataFile)) {
            $rawEx = @file_get_contents($dataFile);
            if ($rawEx) {
                $parsedEx = json_decode($rawEx, true);
                if (is_array($parsedEx)) {
                    $existing = $parsedEx;
                }
            }
        }
        $delIds = array_values(array_unique(array_merge(
            isset($decoded['deletedIds']) && is_array($decoded['deletedIds']) ? $decoded['deletedIds'] : [],
            isset($existing['deletedIds']) && is_array($existing['deletedIds']) ? $existing['deletedIds'] : []
        )));
        $delFlip = array_flip(array_map('strval', $delIds));

        $mergeById = function($exList, $inList, $respectDeleted = true, $isMeeting = false) use ($delFlip) {
            $map = [];
            $order = [];
            foreach ((is_array($inList) ? $inList : []) as $item) {
                if (!is_array($item) || empty($item['id'])) continue;
                $id = (string)$item['id'];
                if ($respectDeleted && isset($delFlip[$id])) continue;
                if (!isset($map[$id])) $order[] = $id;
                $map[$id] = $item;
            }
            foreach ((is_array($exList) ? $exList : []) as $item) {
                if (!is_array($item) || empty($item['id'])) continue;
                $id = (string)$item['id'];
                if ($respectDeleted && isset($delFlip[$id])) continue;
                if (!isset($map[$id])) {
                    $order[] = $id;
                    $map[$id] = $item;
                } elseif ($isMeeting) {
                    $exAg = isset($item['agendaItems']) && is_array($item['agendaItems']) ? count($item['agendaItems']) : 0;
                    $inAg = isset($map[$id]['agendaItems']) && is_array($map[$id]['agendaItems']) ? count($map[$id]['agendaItems']) : 0;
                    if ($exAg > 0 && $inAg === 0) {
                        $map[$id] = array_merge($map[$id], $item);
                    }
                }
            }
            $out = [];
            foreach ($order as $k) {
                if (isset($map[$k])) $out[] = $map[$k];
            }
            return $out;
        };

        $decoded['deletedIds'] = array_slice($delIds, 0, 500);
        $decoded['meetings'] = $mergeById(isset($existing['meetings']) ? $existing['meetings'] : [], isset($decoded['meetings']) ? $decoded['meetings'] : [], true, true);
        $decoded['actions'] = $mergeById(isset($existing['actions']) ? $existing['actions'] : [], isset($decoded['actions']) ? $decoded['actions'] : [], true, false);
        $decoded['announcements'] = $mergeById(isset($existing['announcements']) ? $existing['announcements'] : [], isset($decoded['announcements']) ? $decoded['announcements'] : [], true, false);
        $decoded['approvalRequests'] = $mergeById(isset($existing['approvalRequests']) ? $existing['approvalRequests'] : [], isset($decoded['approvalRequests']) ? $decoded['approvalRequests'] : [], false, false);
        $decoded['logs'] = array_slice($mergeById(isset($existing['logs']) ? $existing['logs'] : [], isset($decoded['logs']) ? $decoded['logs'] : [], false, false), 0, 500);
        $exRev = isset($existing['stateRevision']) ? (int)$existing['stateRevision'] : 0;
        $inRev = isset($decoded['stateRevision']) ? (int)$decoded['stateRevision'] : 0;
        $decoded['stateRevision'] = max($exRev, $inRev) + ($inRev <= $exRev ? 1 : 0);

        file_put_contents($dataFile, json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
        echo json_encode(['status' => 'ok', 'updated_at' => date('c'), 'stateRevision' => $decoded['stateRevision']]);
    } else {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz JSON verisi']);
    }
    exit;
}
?>
