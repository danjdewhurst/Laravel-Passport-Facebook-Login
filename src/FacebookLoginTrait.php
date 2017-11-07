<?php
namespace Danjdewhurst\PassportFacebookLogin;

use Facebook\Facebook;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;

trait FacebookLoginTrait {
    /**
     * Logs a App\User in using a Facebook token via Passport
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Database\Eloquent\Model|null
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function loginFacebook(Request $request)
    {
        try {
            /**
             * Check if the 'fb_token' as passed.
             */
            if ($request->get('fb_token')) {

                /**
                 * Initialise Facebook SDK.
                 */
                $fb = new Facebook([
                    'app_id' => config('facebook.app.id'),
                    'app_secret' => config('facebook.app.secret'),
                    'default_graph_version' => 'v2.5',
                ]);
                $fb->setDefaultAccessToken($request->get('fb_token'));

                /**
                 * Make the Facebook request.
                 */
                $response = $fb->get('/me?locale=en_GB&fields=first_name,last_name,email');
                $fbUser = $response->getDecodedBody();

                /**
                 * Check if the user has already signed up.
                 */
                $userModel = config('auth.providers.users.model');

                /**
                 * Create a new user if they haven't already signed up.
                 */
                $user = $userModel::where('facebook_id', $fbUser['id'])->first();

                if (!$user) {
                    $user = new $userModel();
                    $user->facebook_id = $fbUser['id'];
                    $user->first_name = $fbUser['first_name'];
                    $user->last_name = $fbUser['last_name'];
                    $user->email = $fbUser['email'];
                    $user->password = uniqid('fb_', true); // Random password.
                    $user->save();

                    /**
                     * Attach a role to the user.
                     */
                    if(!is_null(config('facebook.registration.attach_role'))) {
                        $user->attachRole(config('facebook.registration.attach_role'));
                    }
                }                

                return $user;
            }
        } catch (\Exception $e) {
            throw OAuthServerException::accessDenied($e->getMessage());
        }
        return null;
    }
}
