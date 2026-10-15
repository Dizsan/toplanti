<?php
/**
 * DİZSAN KURUMSAL TOPLANTI, AKSİYON & DENETİM SİSTEMİ - PHP BACKEND API (v1.3.0)
 * Ortak Veri Senkronizasyonu + E-Posta Şifre Doğrulama Kodu Gönderimi
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

if ($action === 'send_reset_code' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input');
    $payload = json_decode($rawInput, true);
    $email = isset($payload['email']) ? trim($payload['email']) : '';
    $code = isset($payload['code']) ? trim($payload['code']) : '';
    $name = isset($payload['name']) ? trim($payload['name']) : 'Personel';

    if ($email && $code) {
        $subject = "=?UTF-8?B?" . base64_encode("DİZSAN Toplantı Sistemi - Şifre Sıfırlama Doğrulama Kodu") . "?=";
        $message = "Sayın $name,\n\nDİZSAN Kurumsal Toplantı ve Aksiyon Yönetim Sistemi şifre sıfırlama talebiniz için tek kullanımlık doğrulama kodunuz:\n\nDOĞRULAMA KODU: $code\n\nBu kod 10 dakika boyunca geçerlidir.\n\nİyi çalışmalar dileriz,\nDİZSAN Otomotiv & Servis";
        $headers = "From: bilgi@dizsan.com\r\n" .
                   "Reply-To: bilgi@dizsan.com\r\n" .
                   "Content-Type: text/plain; charset=UTF-8\r\n";
        $mailSent = @mail($email, $subject, $message, $headers);
        echo json_encode([
            'status' => 'ok',
            'mail_sent' => (bool)$mailSent,
            'email' => $email
        ], JSON_UNESCAPED_UNICODE);
    } else {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Eksik e-posta veya doğrulama kodu']);
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
    if ($decoded !== null) {
        file_put_contents($dataFile, json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
        echo json_encode(['status' => 'ok', 'updated_at' => date('c')]);
    } else {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz JSON verisi']);
    }
    exit;
}
?>
