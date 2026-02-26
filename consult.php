<?php
declare(strict_types=1);

/*
 * MaxITTechs Consultation Intake
 * → osTicket API (origin bypass via CURLOPT_RESOLVE)
 * Fail-closed, rate limited, minimal logging
 */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo "Method not allowed.";
    exit;
}

header('Content-Type: text/html; charset=utf-8');

$configPath = __DIR__ . '/.consult_config.php';
if (!is_file($configPath)) {
    http_response_code(500);
    echo "Sorry — we couldn't submit your request right now.";
    exit;
}

$config = require $configPath;

$apiUrl   = (string)($config['osticket_api_url'] ?? '');
$apiKey   = (string)($config['osticket_api_key'] ?? '');
$apiHost  = (string)($config['osticket_api_host'] ?? '');
$originIp = (string)($config['osticket_api_origin_ip'] ?? '');

if ($apiUrl === '' || $apiKey === '' || $apiHost === '' || $originIp === '') {
    http_response_code(500);
    echo "Sorry — we couldn't submit your request right now.";
    exit;
}

/* ==============================
   Rate limiting (3 per 10 mins)
   ============================== */

$ip = $_SERVER['HTTP_CF_CONNECTING_IP']
    ?? $_SERVER['REMOTE_ADDR']
    ?? 'unknown';

$rateDir = sys_get_temp_dir() . '/maxittechs_rate';
if (!is_dir($rateDir)) {
    @mkdir($rateDir, 0700, true);
}

$rateKey  = preg_replace('/[^a-zA-Z0-9\.\-\_]/', '_', $ip);
$rateFile = $rateDir . '/consult_' . $rateKey . '.json';

$now          = time();
$window       = 600;
$maxInWindow  = 3;

$state = ['ts' => $now, 'count' => 0];

if (is_file($rateFile)) {
    $decoded = json_decode((string)@file_get_contents($rateFile), true);
    if (is_array($decoded) && isset($decoded['ts'], $decoded['count'])) {
        $state = $decoded;
    }
}

if (($now - (int)$state['ts']) > $window) {
    $state = ['ts' => $now, 'count' => 0];
}

$state['count']++;

@file_put_contents($rateFile, json_encode($state), LOCK_EX);

if ($state['count'] > $maxInWindow) {
    http_response_code(429);
    echo "Too many requests. Please wait and try again later.";
    exit;
}

/* ==============================
   Honeypot
   ============================== */

if (trim((string)($_POST['website'] ?? '')) !== '') {
    http_response_code(200);
    echo "Thanks — your request has been received.";
    exit;
}

/* ==============================
   Validation
   ============================== */

function field(string $key, int $maxLen, bool $required = true): string {
    $v = trim((string)($_POST[$key] ?? ''));
    if ($required && $v === '') return '';
    if (strlen($v) > $maxLen) $v = substr($v, 0, $maxLen);
    return $v;
}

$company          = field('company', 120);
$name             = field('name', 120);
$email            = field('email', 180);
$phone            = field('phone', 40, false);
$users            = field('users', 10);
$server           = strtolower(field('server', 10));
$m365             = strtolower(field('m365', 10));
$message          = field('message', 2000);
$businessLocation = field('business_location', 200);
$industry         = field('industry', 60, false);
$existingProvider = field('existing_provider', 60);

if ($company === '' || $name === '' || $email === '' || $users === '' || $server === '' || $m365 === '' || $message === '' || $businessLocation === '' || $existingProvider === '') {
    http_response_code(400);
    echo "Please complete all required fields.";
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo "Please enter a valid email address.";
    exit;
}

if (!preg_match('/^\d{1,3}$/', $users)) {
    http_response_code(400);
    echo "Please enter a valid user count.";
    exit;
}

$usersInt = (int)$users;

if ($usersInt < 5 || $usersInt > 75) {
    http_response_code(400);
    echo "We currently support organisations with 5–75 users.";
    exit;
}

if (!in_array($server, ['yes','no'], true) || !in_array($m365, ['yes','no'], true)) {
    http_response_code(400);
    echo "Invalid selection.";
    exit;
}

$allowedProviders = [
    'No provider (currently unmanaged)',
    'Internal IT staff',
    'External MSP',
    'Freelancer / ad-hoc support',
];
if (!in_array($existingProvider, $allowedProviders, true)) {
    http_response_code(400);
    echo "Invalid selection.";
    exit;
}

$allowedIndustries = [
    'Construction', 'Legal', 'Healthcare', 'Finance',
    'Retail', 'Manufacturing', 'Education', 'Professional Services', 'Other',
];
if ($industry !== '' && !in_array($industry, $allowedIndustries, true)) {
    $industry = 'Other';
}

/* ==============================
   Build osTicket payload
   ============================== */

$subject = "New consultation request – " . $company;

$bodyLines = [
    "Company: {$company}",
    "Contact: {$name}",
    "Email: {$email}",
    $phone !== '' ? "Phone: {$phone}" : "Phone: (not provided)",
    "Business location: {$businessLocation}",
    $industry !== '' ? "Industry: {$industry}" : null,
    "Existing IT provider: {$existingProvider}",
    "Users: {$usersInt}",
    "Server: " . strtoupper($server),
    "Microsoft 365: " . strtoupper($m365),
    "",
    "Message:",
    $message,
    "",
    "Source IP: {$ip}",
];
$body = implode("\n", array_values(array_filter($bodyLines, static fn($l) => $l !== null)));

$payload = [
    'name'    => $name,
    'email'   => 'support@maxittechs.info',
    'subject' => $subject,
    'message' => $body,
];

/* ==============================
   cURL to osTicket
   ============================== */

$ch = curl_init($apiUrl);

curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'X-API-Key: ' . $apiKey,
    ],
    CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 10,
    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
    CURLOPT_RESOLVE        => [
        $apiHost . ':443:' . $originIp,
    ],
]);

$resBody = curl_exec($ch);
$err     = curl_error($ch);
$code    = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
curl_close($ch);

/* ==============================
   Minimal log
   ============================== */

$logLine = sprintf(
    "[%s] consult ip=%s code=%d company=%s email=%s\n",
    gmdate('c'),
    $ip,
    $code,
    preg_replace('/[^a-zA-Z0-9 \-\_\.\&]/', '', $company),
    $email
);

@file_put_contents(__DIR__ . '/consult.log', $logLine, FILE_APPEND);

/* ==============================
   Fail closed
   ============================== */

if ($err !== '' || $code < 200 || $code >= 300) {
    http_response_code(500);
    echo "Sorry — we couldn't submit your request right now. Please email support@maxittechs.info.";
    exit;
}

http_response_code(200);
echo "Thanks — your request has been received. We’ll respond within 1 business day.";
