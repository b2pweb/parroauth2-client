<?php

namespace Parroauth2\Client\OpenID\EndPoint;

use Base64Url\Base64Url;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint as BaseAuthorizationEndPoint;

use function implode;
use function is_array;

/**
 * Authorization endpoint for OpenID Connect provider
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
 */
class AuthorizationEndPoint extends BaseAuthorizationEndPoint
{
    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view.
     * If the display parameter is not specified, this is the default display mode.
     */
    public const DISPLAY_PAGE = 'page';

    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window.
     * The popup User Agent window should be of an appropriate size for a login-focused dialog
     * and should not obscure the entire window that it is popping up over.
     */
    public const DISPLAY_POPUP = 'popup';

    /**
     * The Authorization Server SHOULD display the authentication and consent
     * UI consistent with a device that leverages a touch interface.
     */
    public const DISPLAY_TOUCH = 'touch';

    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
     */
    public const DISPLAY_WAP = 'wap';

    /**
     * The Authorization Server MUST NOT display any authentication or consent user interface pages.
     * An error is returned if an End-User is not already authenticated or the Client does not have pre-configured
     * consent for the requested Claims or does not fulfill other conditions for processing the request.
     * The error code will typically be login_required, interaction_required, or another code.
     * This can be used as a method to check for existing authentication and/or consent.
     */
    public const PROMPT_NONE = 'none';

    /**
     * The Authorization Server SHOULD prompt the End-User for reauthentication.
     * If it cannot reauthenticate the End-User, it MUST return an error, typically login_required.
     */
    public const PROMPT_LOGIN = 'login';

    /**
     * The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client.
     * If it cannot obtain consent, it MUST return an error, typically consent_required.
     */
    public const PROMPT_CONSENT = 'consent';

    /**
     * The Authorization Server SHOULD prompt the End-User to select a user account.
     * This enables an End-User who has multiple accounts at the Authorization Server to select amongst the multiple
     * accounts that they might have current sessions for. If it cannot obtain an account selection choice made by the End-User,
     * it MUST return an error, typically account_selection_required.
     */
    public const PROMPT_SELECT_ACCOUNT = 'select_account';

    /**
     * {@inheritdoc}
     *
     * @psalm-mutation-free
     */
    public function scope(array $scopes): BaseAuthorizationEndPoint
    {
        if (!in_array('openid', $scopes)) {
            array_unshift($scopes, 'openid');
        }

        /** @var static */
        return BaseAuthorizationEndPoint::scope($scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function uri(array $parameters = []): string
    {
        if (isset($this->parameters()['scope'])) {
            return parent::uri($parameters);
        }

        // Add the scope parameter if not yet set
        return $this->set('scope', 'openid')->uri($parameters);
    }

    /**
     * Set the nonce
     *
     * @param string|null $nonce The nonce, or null to generate it
     *
     * @return static
     */
    public function nonce(?string $nonce = null): self
    {
        if ($nonce === null) {
            $nonce = Base64Url::encode(random_bytes(32));
        }

        return $this->set('nonce', $nonce);
    }

    /**
     * ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User
     *
     * @param self::DISPLAY_* $mode Display mode. Should be one of the DISPLAY_* constants
     * @return self
     */
    public function display(string $mode): self
    {
        return $this->set('display', $mode);
    }

    /**
     * Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization
     * Server prompts the End-User for reauthentication and consent.
     *
     * The prompt parameter can be used by the Client to make sure that the End-User is still present
     * for the current session or to bring attention to the request.
     * If this parameter contains none with any other value, an error is returned.
     *
     * Use the PROMPT_* constants to define the prompt mode
     *
     * @param list<string>|string $mode Prompt modes. Can be an array of prompt mode, or a space delimited string
     *
     * @return self
     */
    public function prompt($mode): self
    {
        if (is_array($mode)) {
            $mode = implode(' ', $mode);
        }

        return $this->set('prompt', $mode);
    }

    /**
     * Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last time the End-User
     * was actively authenticated by the OP.
     *
     * If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User.
     * When max_age is used, the ID Token returned MUST include an auth_time Claim Value.
     *
     * @param int $maxAge The maximum authentication age in seconds
     *
     * @return self
     */
    public function maxAge(int $maxAge): self
    {
        return $this->set('max_age', $maxAge);
    }

    /**
     * End-User's preferred languages and scripts for the user interface, represented as a space-separated list
     * of BCP47 [RFC5646] language tag values, ordered by preference.
     * For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada,
     * then French (without a region designation), followed by English (without a region designation).
     * An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider.
     *
     * @param string|list<string> $locale The locale, or a list of locale
     * @return self
     */
    public function uiLocales($locale): self
    {
        if (is_array($locale)) {
            $locale = implode(' ', $locale);
        }

        return $this->set('ui_locales', $locale);
    }

    /**
     * ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current
     * or past authenticated session with the Client.
     *
     * If the End-User identified by the ID Token is logged in or is logged in by the request,
     * then the Authorization Server returns a positive response; otherwise, it SHOULD return an error, such as login_required.
     * When possible, an id_token_hint SHOULD be present when prompt=none is used and an invalid_request error
     * MAY be returned if it is not; however, the server SHOULD respond successfully when possible, even if it is not present.
     * The Authorization Server need not be listed as an audience of the ID Token when it is used as an id_token_hint value.
     *
     * If the ID Token received by the RP from the OP is encrypted, to use it as an id_token_hint,
     * the Client MUST decrypt the signed ID Token contained within the encrypted ID Token.
     * The Client MAY re-encrypt the signed ID token to the Authentication Server using a key that enables
     * the server to decrypt the ID Token, and use the re-encrypted ID token as the id_token_hint value.
     *
     * @param string $idToken The ID token
     *
     * @return self
     */
    public function idTokenHint(string $idToken): self
    {
        return $this->set('id_token_hint', $idToken);
    }

    /**
     * Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary).
     *
     * This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier)
     * and then wants to pass that value as a hint to the discovered authorization service.
     *
     * It is RECOMMENDED that the hint value match the value used for discovery.
     * This value MAY also be a phone number in the format specified for the phone_number Claim.
     * The use of this parameter is left to the OP's discretion.
     *
     * @param string $loginHint The login hint
     * @return self
     */
    public function loginHint(string $loginHint): self
    {
        return $this->set('login_hint', $loginHint);
    }

    /**
     * Requested Authentication Context Class Reference values.
     *
     * Space-separated string that specifies the acr values that the Authorization Server is being requested
     * to use for processing this Authentication Request, with the values appearing in order of preference.
     * The Authentication Context Class satisfied by the authentication performed is returned as the acr Claim Value.
     * The acr Claim is requested as a Voluntary Claim by this parameter.
     *
     * @param string|list<string> $acrValues The acr values as space-separated string, or a list of acr values
     *
     * @return self
     */
    public function acrValues($acrValues): self
    {
        if (is_array($acrValues)) {
            $acrValues = implode(' ', $acrValues);
        }

        return $this->set('acr_values', $acrValues);
    }
}
