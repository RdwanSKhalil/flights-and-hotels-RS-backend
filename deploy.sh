#!/bin/bash

# Install dependencies
composer install --no-interaction --optimize-autoloader

# Clear and cache config
php artisan config:clear
php artisan cache:clear
php artisan config:cache

# Run migrations
php artisan migrate --force

# (Optional) Clear route & view cache
php artisan route:cache
php artisan view:cache

echo "Deployment finished!"
