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
        file_put_contents($dataFile, json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
        echo json_encode(['status' => 'ok', 'updated_at' => date('c')]);
    } else {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz JSON verisi']);
    }
    exit;
}
?>
