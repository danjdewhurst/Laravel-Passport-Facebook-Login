# Laravel Passport Facebook Login
Provides a new Laravel Passport Grant Client named `facebook_login`, allowing you to log a user in with just their Facebook Login token.

A new user will be created (and optionally assigned to an role - `$user->attachRole(ID)`) if the email address doesn't exist.

## Installation:
Install with composer `composer require danjdewhurst/laravel-passport-facebook-login`. Use major version 1 for Passport 4 and below Laravel 5.6 compatibility.

### Versions:
* Laravel 5.6 and Passport 4.0 only supported at this time

## Dependencies:
* `"laravel/passport": "~5.0"`
* `"facebook/graph-sdk": "~5.6"`

## Setup:
* ***Using Laravel 5.4 or below?*** add `Danjdewhurst\PassportFacebookLogin\FacebookLoginGrantProvider::class` to your list of providers **after** `Laravel\Passport\PassportServiceProvider`. Laravel 5.5 uses auto-discovery, so manual service registration is no longer required.
* Add `Danjdewhurst\PassportFacebookLogin\FacebookLoginTrait` Trait to your `User` model (or whatever model you have configured to work with Passport).
* Run `php artisan vendor:publish`, this will create a `config/facebook.php` file.
* Enter your Facebook App details in your `.env` file: `FACEBOOK_APP_ID` and `FACEBOOK_APP_SECRET`.
* Optional: To automatically attach a role (https://github.com/Zizaco/entrust) to new users, use the 'ATTACH_ROLE' env setting.

**Config:**
```php
    /*
    |--------------------------------------------------------------------------
    | Application
    |--------------------------------------------------------------------------
    |
    | The facebook ID and secret from the developer's page
    |
    */

    'app' => [
        'id' => env('FACEBOOK_APP_ID'),
        'secret' => env('FACEBOOK_APP_SECRET'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Registration Fields
    |--------------------------------------------------------------------------
    |
    | The name of the fields on the user model that need to be updated,
    | if null, they shall not be updated. (valid for name, first_name, last_name)
    |
    */

    'registration' => [
        'facebook_id' => env('FACEBOOK_ID_COLUMN', 'facebook_id'),
        'user_id'     => env('USER_ID', 'id'),
        'email'       => env('EMAIL_COLUMN', 'email'),
        'password'    => env('PASSWORD_COLUMN', 'password'),
        'first_name'  => env('FIRST_NAME_COLUMN', 'first_name'),
        'last_name'   => env('LAST_NAME_COLUMN', 'last_name'),
        'name'        => env('NAME_COLUMN', 'name'),
        'attach_role' => env('ATTACH_ROLE', null),
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

## Credits:
* https://github.com/mirkco/Laravel-Passport-Facebook-Login
* https://github.com/mikemclin/passport-custom-request-grant
