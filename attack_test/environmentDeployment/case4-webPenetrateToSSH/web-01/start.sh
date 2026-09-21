#!/bin/bash
set -e

mkdir -p /var/www/html/uploads
chown www-data:www-data /var/www/html/uploads
chmod 777 /var/www/html/uploads

# Start PHP-FPM
PHP_FPM=$(command -v php-fpm8.1 2>/dev/null || command -v php-fpm8.3 2>/dev/null || command -v php-fpm 2>/dev/null)
$PHP_FPM --daemonize

# Start Nginx (foreground, PID 1)
exec nginx -g 'daemon off;'
