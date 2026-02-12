FROM php:8.2-fpm

RUN apt-get update && \
    apt-get install -y git unzip && \
    rm -rf /var/lib/apt/lists/*

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader
RUN composer require monolog/monolog

COPY . /var/www/html/

ENV APP_ENV=production

EXPOSE 9000

CMD ["php-fpm"]
