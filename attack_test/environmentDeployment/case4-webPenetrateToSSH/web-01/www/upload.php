<?php
/**
 * SecureShare file upload handler.
 *
 * VULNERABILITY NOTES (for lab exercise — NOT production code):
 *   1. MIME type check uses client-supplied Content-Type header → trivially spoofable
 *   2. Extension blacklist misses .phtml / .phar / .inc
 *   3. No file content / magic-byte inspection
 *   4. Original filename preserved (no randomization)
 *   5. Nginx processes .phtml as PHP (see nginx.conf)
 *
 * Attack vector:
 *   Save a PHP webshell as shell.phtml, upload with Content-Type: image/jpeg
 *   → bypasses both MIME check and extension blacklist
 *   → accessible at /uploads/shell.phtml
 */

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) {
    header('Location: index.php?status=err&msg=' . urlencode('请选择文件'));
    exit;
}

$file     = $_FILES['file'];
$filename = basename($file['name']);
$ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$errors   = [];

// --- Security Check 1: MIME type ---
$allowed_mimes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'text/plain',
];
if (!in_array($file['type'], $allowed_mimes)) {
    $errors[] = "不允许的文件类型: {$file['type']}";
}

// --- Security Check 2: Extension blacklist ---
$blocked_extensions = [
    'php', 'php3', 'php4', 'php5', 'php7', 'phps',
    'exe', 'dll', 'so',
    'sh', 'bash', 'bat', 'cmd', 'ps1',
    'py', 'pl', 'rb',
    'jsp', 'asp', 'aspx', 'cgi',
];
if (in_array($ext, $blocked_extensions)) {
    $errors[] = "禁止的扩展名: .{$ext}";
}

// --- Security Check 3: File size (5 MB) ---
if ($file['size'] > 5 * 1024 * 1024) {
    $errors[] = '文件过大 (最大 5MB)';
}

// --- Security Check 4: Upload error ---
if ($file['error'] !== UPLOAD_ERR_OK) {
    $errors[] = '上传出错 (code ' . $file['error'] . ')';
}

if ($errors) {
    $msg = implode('; ', $errors);
    header('Location: index.php?status=err&msg=' . urlencode($msg));
    exit;
}

// --- Save ---
$upload_dir = __DIR__ . '/uploads';
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}
$target = $upload_dir . '/' . $filename;

if (move_uploaded_file($file['tmp_name'], $target)) {
    $msg = "上传成功: {$filename} (" . round($file['size'] / 1024) . ' KB)';
    header('Location: index.php?status=ok&msg=' . urlencode($msg));
} else {
    header('Location: index.php?status=err&msg=' . urlencode('保存失败'));
}
