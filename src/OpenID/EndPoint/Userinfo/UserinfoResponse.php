<?php

namespace Parroauth2\Client\OpenID\EndPoint\Userinfo;

/**
 * Response of the userinfo endpoint
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.3.2
 *
 * @psalm-immutable
 */
class UserinfoResponse
{
    /**
     * @var array<string, mixed>
     */
    private $data;

    /**
     * UserinfoResponse constructor.
     *
     * @param array<string, mixed> $data
     */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    /**
     * Get the subject (i.e. The user identifier)
     *
     * @return string
     */
    public function subject(): string
    {
        return $this->data['sub'];
    }

    /**
     * End-User's full name in displayable form including all name parts,
     * possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
     *
     * @return string|null
     */
    public function name(): ?string
    {
        return $this->data['name'] ?? null;
    }

    /**
     * Given name(s) or first name(s) of the End-User.
     * Note that in some cultures, people can have multiple given names;
     * all can be present, with the names being separated by space characters.
     *
     * @return string|null
     */
    public function givenName(): ?string
    {
        return $this->data['given_name'] ?? null;
    }

    /**
     * Surname(s) or last name(s) of the End-User.
     * Note that in some cultures, people can have multiple family names or no family name;
     * all can be present, with the names being separated by space characters.
     *
     * @return string|null
     */
    public function familyName(): ?string
    {
        return $this->data['family_name'] ?? null;
    }

    /**
     * Middle name(s) of the End-User.
     * Note that in some cultures, people can have multiple middle names;
     * all can be present, with the names being separated by space characters.
     * Also note that in some cultures, middle names are not used.
     *
     * @return string|null
     */
    public function middleName(): ?string
    {
        return $this->data['middle_name'] ?? null;
    }

    /**
     * Casual name of the End-User that may or may not be the same as the given_name.
     * For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
     *
     * @return string|null
     */
    public function nickname(): ?string
    {
        return $this->data['nickname'] ?? null;
    }

    /**
     * Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe.
     * This value MAY be any valid JSON string including special characters such as @, /, or whitespace.
     * The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
     *
     * @return string|null
     */
    public function preferredUsername(): ?string
    {
        return $this->data['preferred_username'] ?? null;
    }

    /**
     * URL of the End-User's profile page.
     * The contents of this Web page SHOULD be about the End-User.
     *
     * @return string|null
     */
    public function profile(): ?string
    {
        return $this->data['profile'] ?? null;
    }

    /**
     * URL of the End-User's profile picture.
     * This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file),
     * rather than to a Web page containing an image.
     * Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying
     * when describing the End-User, rather than an arbitrary photo taken by the End-User.
     *
     * @return string|null
     */
    public function picture(): ?string
    {
        return $this->data['picture'] ?? null;
    }

    /**
     * URL of the End-User's Web page or blog.
     * This Web page SHOULD contain information published by the End-User
     * or an organization that the End-User is affiliated with.
     *
     * @return string|null
     */
    public function website(): ?string
    {
        return $this->data['website'] ?? null;
    }

    /**
     * End-User's preferred e-mail address.
     * Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax.
     * The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
     *
     * @return string|null
     */
    public function email(): ?string
    {
        return $this->data['email'] ?? null;
    }

    /**
     * True if the End-User's e-mail address has been verified; otherwise false.
     * When this Claim Value is true, this means that the OP took affirmative steps to ensure
     * that this e-mail address was controlled by the End-User at the time the verification was performed.
     * The means by which an e-mail address is verified is context-specific,
     * and dependent upon the trust framework or contractual agreements within which the parties are operating.
     *
     * @return bool|null
     */
    public function emailVerified(): ?bool
    {
        return $this->data['email_verified'] ?? null;
    }

    /**
     * End-User's gender.
     * Values defined by this specification are female and male.
     * Other values MAY be used when neither of the defined values are applicable.
     *
     * @return string|null
     */
    public function gender(): ?string
    {
        return $this->data['gender'] ?? null;
    }

    /**
     * End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format.
     * The year MAY be 0000, indicating that it is omitted.
     * To represent only the year, YYYY format is allowed.
     * Note that depending on the underlying platform's date related function,
     * providing just year can result in varying month and day,
     * so the implementers need to take this factor into account to correctly process the dates.
     *
     * @return string|null
     */
    public function birthdate(): ?string
    {
        return $this->data['birthdate'] ?? null;
    }

    /**
     * String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone.
     * For example, Europe/Paris or America/Los_Angeles.
     *
     * @return string|null
     */
    public function zoneinfo(): ?string
    {
        return $this->data['zoneinfo'] ?? null;
    }

    /**
     * End-User's locale, represented as a BCP47 [RFC5646] language tag.
     * This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase
     * and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash.
     * For example, en-US or fr-CA. As a compatibility note,
     * some implementations have used an underscore as the separator rather than a dash,
     * for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
     *
     * @return string|null
     */
    public function locale(): ?string
    {
        return $this->data['locale'] ?? null;
    }

    /**
     * End-User's preferred telephone number.
     * E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400.
     * If the phone number contains an extension, it is RECOMMENDED that the extension be represented using
     * the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
     *
     * @return string|null
     */
    public function phoneNumber(): ?string
    {
        return $this->data['phone_number'] ?? null;
    }

    /**
     * True if the End-User's phone number has been verified; otherwise false.
     * When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number
     * was controlled by the End-User at the time the verification was performed.
     * The means by which a phone number is verified is context-specific,
     * and dependent upon the trust framework or contractual agreements within which the parties are operating.
     * When true, the phone_number Claim MUST be in E.164 format
     * and any extensions MUST be represented in RFC 3966 format.
     *
     * @return bool|null
     */
    public function phoneNumberVerified(): ?bool
    {
        return $this->data['phone_number_verified'] ?? null;
    }

    /**
     * End-User's preferred postal address.
     * The value of the address member is a JSON [RFC4627] structure containing
     * some or all of the members defined in Section 5.1.1.
     *
     * @return array|null
     */
    public function address(): ?array
    {
        return $this->data['address'] ?? null;
    }

    /**
     * Time the End-User's information was last updated.
     * Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z
     * as measured in UTC until the date/time.
     *
     * @return int|null
     */
    public function updatedAt(): ?int
    {
        return $this->data['updated_at'] ?? null;
    }

    /**
     * Get a claim value
     *
     * @param string $name The claim name
     * @param mixed $default The default value to return, when not defined on the response
     *
     * @return mixed
     */
    public function claim(string $name, $default = null)
    {
        return $this->data[$name] ?? $default;
    }

    /**
     * Get all claims of the userinfo
     *
     * @return array
     */
    public function claims(): array
    {
        return $this->data;
    }
}
