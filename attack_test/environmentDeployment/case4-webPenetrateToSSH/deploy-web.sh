#!/bin/bash
# ============================================================
# Web Penetration Target — Host 91 (OpenEuler)
# (Web 渗透靶机部署 — 91)
#
# Prerequisite: deploy-nginx-base.sh
# Deploy path: /var/www/html/webshell/
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

APP_DIR="/var/www/html/webshell"

echo "========== 部署 webshell 应用 → ${APP_DIR} =========="
lab_claim_directory "${APP_DIR}" app-webshell
mkdir -p "${APP_DIR}/uploads"
chmod 777 "${APP_DIR}/uploads"

# --- index.php ---
cat > "${APP_DIR}/index.php" << 'PHPEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureShare - 文件共享平台</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #f0f2f5; color: #333; }
header { background: linear-gradient(135deg, #1a73e8, #0d47a1); color: #fff; padding: 20px 0; text-align: center; }
header h1 { font-size: 24px; font-weight: 600; }
header p { font-size: 13px; opacity: 0.8; margin-top: 4px; }
.container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 20px; }
.card h2 { font-size: 18px; margin-bottom: 16px; color: #1a73e8; }
.upload-form { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.upload-form input[type="file"] { flex: 1; min-width: 200px; padding: 8px; border: 2px dashed #ccc; border-radius: 6px; cursor: pointer; }
.upload-form input[type="file"]:hover { border-color: #1a73e8; }
.upload-form button { background: #1a73e8; color: #fff; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-size: 14px; }
.upload-form button:hover { background: #1557b0; }
.security-badge { display: inline-flex; align-items: center; gap: 4px; background: #e8f5e9; color: #2e7d32; font-size: 12px; padding: 4px 10px; border-radius: 12px; margin-top: 12px; }
.msg { padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
.msg.ok { background: #e8f5e9; color: #2e7d32; }
.msg.err { background: #fce4ec; color: #c62828; }
.file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; }
.file-item { border: 1px solid #e0e0e0; border-radius: 6px; padding: 12px; text-align: center; transition: box-shadow 0.2s; }
.file-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.12); }
.file-item .icon { font-size: 36px; margin-bottom: 8px; }
.file-item .name { font-size: 13px; word-break: break-all; color: #555; }
.file-item a { text-decoration: none; color: inherit; display: block; }
.empty { color: #999; font-size: 14px; text-align: center; padding: 40px; }
footer { text-align: center; padding: 20px; color: #999; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>SecureShare</h1>
  <p>企业内部文件共享平台 v2.1.4</p>
</header>
<div class="container">
  <div class="card">
    <h2>上传文件</h2>
    <?php if (isset($_GET['msg'])): ?>
      <div class="msg <?= $_GET['status'] === 'ok' ? 'ok' : 'err' ?>">
        <?= htmlspecialchars($_GET['msg']) ?>
      </div>
    <?php endif; ?>
    <form class="upload-form" action="/webshell/upload.php" method="POST" enctype="multipart/form-data">
      <input type="file" name="file" required>
      <button type="submit">上传</button>
    </form>
    <div class="security-badge">文件类型安全检查已启用</div>
  </div>
  <div class="card">
    <h2>已上传文件</h2>
    <?php
    $upload_dir = __DIR__ . '/uploads';
    if (!is_dir($upload_dir)) mkdir($upload_dir, 0777, true);
    $files = array_diff(scandir($upload_dir), ['.', '..']);
    if (empty($files)): ?>
      <div class="empty">暂无文件</div>
    <?php else: ?>
      <div class="file-grid">
      <?php foreach ($files as $f):
        $path = "/webshell/uploads/" . $f;
        $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        $is_img = in_array($ext, ['jpg','jpeg','png','gif','webp']);
        $icon = $is_img ? '🖼️' : '📄';
      ?>
        <div class="file-item">
          <a href="<?= htmlspecialchars($path) ?>" target="_blank">
            <div class="icon"><?= $icon ?></div>
            <div class="name"><?= htmlspecialchars($f) ?></div>
          </a>
        </div>
      <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>
</div>
<footer>SecureShare &copy; 2026 — PHP <?= phpversion() ?> / <?= $_SERVER['SERVER_SOFTWARE'] ?></footer>
</body>
</html>
PHPEOF

# --- upload.php ---
cat > "${APP_DIR}/upload.php" << 'PHPEOF'
<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) {
    header('Location: /webshell/index.php?status=err&msg=' . urlencode('请选择文件'));
    exit;
}

$file     = $_FILES['file'];
$filename = basename($file['name']);
$ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$errors   = [];

$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'text/plain'];
if (!in_array($file['type'], $allowed_mimes)) {
    $errors[] = "不允许的文件类型: {$file['type']}";
}

$blocked = ['php','php3','php4','php5','php7','phps','exe','dll','so','sh','bash','bat','cmd','ps1','py','pl','rb','jsp','asp','aspx','cgi'];
if (in_array($ext, $blocked)) {
    $errors[] = "禁止的扩展名: .{$ext}";
}

if ($file['size'] > 5 * 1024 * 1024) {
    $errors[] = '文件过大 (最大 5MB)';
}

if ($file['error'] !== UPLOAD_ERR_OK) {
    $errors[] = '上传出错 (code ' . $file['error'] . ')';
}

if ($errors) {
    header('Location: /webshell/index.php?status=err&msg=' . urlencode(implode('; ', $errors)));
    exit;
}

$upload_dir = __DIR__ . '/uploads';
if (!is_dir($upload_dir)) mkdir($upload_dir, 0777, true);

if (move_uploaded_file($file['tmp_name'], $upload_dir . '/' . $filename)) {
    $msg = "上传成功: {$filename} (" . round($file['size'] / 1024) . ' KB)';
    header('Location: /webshell/index.php?status=ok&msg=' . urlencode($msg));
} else {
    header('Location: /webshell/index.php?status=err&msg=' . urlencode('保存失败'));
}
PHPEOF

chown -R nginx:nginx "${APP_DIR}"
chmod 777 "${APP_DIR}/uploads"
nginx -t && systemctl reload nginx

echo "  部署完成: http://10.66.6.91/webshell/"
curl -s -o /dev/null -w "  验证: HTTP %{http_code}\n" http://127.0.0.1/webshell/
