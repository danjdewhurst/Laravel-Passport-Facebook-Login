# Laravel Passport Facebook Login
Provides a new Laravel Passport Grant Client named `facebook_login`, allowing you to log a user in with just their Facebook Login token.

A new user will be created (and optionally assigned to an EnTrust role) if the email address doesn't exist.

## Installation:
Install with composer `composer require danjdewhurst/laravel-passport-facebook-login`

### Versions:
* Laravel 5.5 and Passport 4.0 only supported at this time

## Dependencies:
* `"laravel/passport": "^4.0"`
* `"facebook/graph-sdk": "^5.6"`

## Setup:
### Laravel 5.5+
Laravel uses auto-discovery.

### Laravel 5.4 or lower
Add `Danjdewhurst\PassportFacebookLogin\FacebookLoginGrantProvider::class` to your list of providers **after** `Laravel\Passport\PassportServiceProvider`.

* Add `Danjdewhurst\PassportFacebookLogin\FacebookLoginTrait` Trait to your `User` model (or whatever model you have configured to work with Passport).
* Run `php artisan vendor:publish`, this will create a `config/facebook.php` file. More options will be added here in the future.
* Enter your Facebook App details in your `.env` file: `FACEBOOK_APP_ID` and `FACEBOOK_APP_SECRET`.
* Optional: To automatically attach a role to new users, amend the following in the config file:
```php
    'registration' => [
        'attach_role' => 1, // ID of the role
    ],
```

## How To Use:

* Make a **POST** request to `https://your-site.com/oauth/token`.
* The POST body should contain
    1. `grant_type` = `facebook_login`
    2. `fb_token` = `{token from facebook login}`.
    3. client_id
    4. client_secret
* An `access_token` and `refresh_token` will be returned if successful.

## Assumptions:
* Your `User` model has the folowing fields:
* * `facebook_id`
* * `name`
* * `email`
* * `password`

## Credits:
* https://github.com/mirkco/Laravel-Passport-Facebook-Login
* https://github.com/mikemclin/passport-custom-request-grant
