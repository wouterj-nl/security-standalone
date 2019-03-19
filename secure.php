<?php

use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserChecker;

require 'vendor/autoload.php';

/*************
 * 1 AUTHENTICATION
 *      Who are you?
 */
// UsernamePasswordToken contains, you guessed it, a username and a password. At
// this stage, it contains plain information from the user (i.e. by submitting a
// login form, or passing it as arguments to a console command).
// 'cli' is just an "identifier" we use later on
$inputToken = new UsernamePasswordToken('wouter', 'pa$$word', 'cli');

// Users have to come from somewhere. The InMemory provider simply takes an array.
// You can also use more advanced user providers, like one loading from a database
// or an LDAP server.
$userProvider = new InMemoryUserProvider([
    'wouter' => ['password' => 'pa$$word', 'roles' => ['TITLE_SUPERVISOR']],
]);
// Finally, we also need to have an EncoderFactoryInterface, which is able to encode
// passwords of a user and check whether the input password is correct.
$encoderFactory = new EncoderFactory([
    User::class => new PlaintextPasswordEncoder(),
]);

// An AuthenticationManagerInterface authenticates a plain token from the user and
// transforms it into an "authenticated" one.
// The AuthenticationProviderManager is the implementation provided by Symfony, it
// iterators over a list of AuthenticationProviderInterface implementations and uses
// the first provider supporting the token.
$authenticationManager = new AuthenticationProviderManager([
    // The DaoAuthenticationProvider is one of many providers in Symfony. DAO means
    // Data Access Object. It indicates it uses a UserProviderInterface to find the
    // user based on the token.
    new DaoAuthenticationProvider(
        $userProvider,
        // A UserCheckerInterface checks "flags" on a user. I.e. it can check if an account
        // is active, not banned, etc.
        new UserChecker(),
        'cli', // hey, this looks familiar! This is the same identifier used on the token
               // it is used to (a) make sure we're authenticating a token of our own
               // application and (b) we know exactly which authentication provider was
               // used (i.e. we can have multiple providers supporting the same token)
        $encoderFactory
    )

    // Other authentication providers use other ways of fetching the user. I.e. the
    // LdapBindAuthenticationProvider uses an LDAP server, RememberMeAuthenticationProvider
    // a remember me cookie and AnonymousAuthenticationProvider always returns the Anon user
]);

try {
    // Pfew, we've set-up authentication. Now, all these lines for one simple method call: We ask
    // the authentication manager to transform our "raw input token" into an "authenticated token".
    $authenticatedToken = $authenticationManager->authenticate($inputToken);
} catch (AuthenticationException $exception) {
    // in authentication was not successful (i.e. something wrong with our set-up or user provided
    // wrong credentials), an exception is thrown.

    // messageKey is a user safe error. We often don't want to reveal all details in security
    // errors, to avoid giving a hacker hints on what's correct or incorrect.
    echo str_replace(
        array_keys($exception->getMessageData()),
        array_values($exception->getMessageData()),
        $exception->getMessageKey()
    );
    exit(1);
}

/*************
 * 2 AUTHORIZATION
 *      Are you allowed to do this?
 */
// The AccessDecisionManagerInterface is the manager of authorization in the Security component.
// By default, only AccessDecisionManager is provided, which uses a list of Voter to determine if
// the authorized token is allowed to do an action.
$accessDecisionManager = new AccessDecisionManager(
    [
        // The role voter checks security attributes starting with the provided string and sees
        // if $loggedInUser->getRoles() contains this attribute.
        new RoleVoter('TITLE_'),

        // Other votes include a RoleHierarchyVoter (a RoleVoter that supports hierarchy, i.e. every
        // statements like "admin is a user") and an AuthenticatedVoter (which can check whether the
        // current token is authenticated, anonymous, etc).
    ]
);

// The authenticated token contains the logged in user provided by InMemoryUserProvider
$username = $authenticatedToken->getUser()->getUsername();

// We can use decide() to "decide" whether a user is allowed to do something. We pass it the
// authenticated token and a list of security attribute to base our decision on.
$isSupervisor = $accessDecisionManager->decide($authenticatedToken, ['TITLE_SUPERVISOR']) ? 'yes' : 'no';

// We didn't configure a voter for this attribute, so false is always returned. We can change
// this by writing our own action-based Voter for editing/showing users.
$canEditUser = $accessDecisionManager->decide($authenticatedToken, ['EDIT'], $authenticatedToken->getUser()) ? 'yes' : 'no';

echo <<<EOT
Hello {$username}!
Are you a supervisor?  {$isSupervisor}
Can you edit USER?     {$canEditUser}
EOT;
