<?php

namespace vakata\authentication\saml;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationException;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * EAuth authentication.
 */
class EAuth implements AuthenticationInterface
{
    protected string $providerID;
    protected string $serviceID;
    protected string $returnURL;
    protected string $metaURL;
    protected string $privatePEM;
    protected ?string $certificatePEM;
    protected ?string $remotePEM;
    protected ?string $id;

    public function __construct(
        string $providerID,
        string $serviceID,
        string $returnURL,
        string $metaURL,
        string $privatePEM,
        ?string $certificatePEM = null,
        ?string $remotePEM = null,
        ?string $id = null
    ) {
        $this->providerID = $providerID;
        $this->serviceID = $serviceID;
        $this->returnURL = $returnURL;
        $this->metaURL = $metaURL;
        $this->privatePEM = $privatePEM;
        $this->certificatePEM = $certificatePEM;
        $this->remotePEM = $remotePEM;
        $this->id = $id;
    }

    public function request(string $level = 'HIGH', array $attributes = []): string
    {
        $id = $this->id ?? 'id_' . md5(microtime());
        $xml = '<' . '?xml version="1.0" encoding="UTF-8"?>
        <samlp:AuthnRequest
            AssertionConsumerServiceURL="{returnURL}"
            Destination="https://eauth.egov.bg/SingleSignOnService"
            ForceAuthn="true" ID="{id}"
            IsPassive="false" IssueInstant="{datetime}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            ProviderName="id.stampit.org" Version="2.0"
            xmlns:egovbga="urn:bg:egov:eauth:2.0:saml:ext"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
            <saml:Issuer>{metaURL}</saml:Issuer>
            <samlp:Extensions>
                <egovbga:RequestedService>
                    <egovbga:Service>{serviceID}</egovbga:Service>
                    <egovbga:Provider>{providerID}</egovbga:Provider>
                    <egovbga:LevelOfAssurance>{level}</egovbga:LevelOfAssurance>
                </egovbga:RequestedService>
                <egovbga:RequestedAttributes xmlns:egovbga="urn:bg:egov:eauth:2.0:saml:ext">
                    {attributes}
                </egovbga:RequestedAttributes>
            </samlp:Extensions>
            <samlp:NameIDPolicy AllowCreate="true"/>
        </samlp:AuthnRequest>';
        $attr = '';
        foreach ($attributes as $a) {
            if (
                in_array(
                    $a,
                    [
                        'email',
                        'phone',
                        'latinName',
                        'birthName',
                        'dateOfBirth',
                        'gender',
                        'placeOfBirth',
                        'canonicalResidenceAddress',
                        'X509Certificate'
                    ],
                    true
                )
            ) {
                $attr .= '<egovbga:RequestedAttribute FriendlyName="' . $a . '"
                    Name="urn:egov:bg:eauth:2.0:attributes:' . $a . '"
                    NameFormat="urn:oasis:names:tc:saml2:2.0:attrname-format:uri" isRequired="true">
                    <egovbga:AttributeValue>urn:egov:bg:eauth:2.0:attributes:' . $a . '</egovbga:AttributeValue>
                </egovbga:RequestedAttribute>';
            }
        }
        $xml = str_replace(
            [
                '{datetime}',
                '{returnURL}',
                '{id}',
                '{metaURL}',
                '{serviceID}',
                '{providerID}',
                '{level}',
                '{attributes}',
            ],
            [
                gmdate('Y-m-d\\TH:i:s\\Z'),
                $this->returnURL,
                $id,
                $this->metaURL,
                $this->serviceID,
                $this->providerID,
                $level,
                $attr
            ],
            $xml
        );
        return $this->sign($xml);
    }
    protected function response(string $response): array
    {
        $id = $this->id ?? ('id_' . md5(microtime()));
        $response = base64_decode($response);
        $response = preg_replace(['(\<[a-z0-9]+\:)i', '(\</[a-z0-9]+\:)i'], ['<', '</'], $response) ?? '';
        $xml = simplexml_load_string($response);
        if (!$xml) {
            throw new \Exception('Could not parse XML');
        }
        if ((string)$xml->Status->StatusCode['Value'] !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            throw new \Exception('Could not login');
        }
        $key = (string)$xml->EncryptedAssertion->EncryptedData->KeyInfo->EncryptedKey->CipherData->CipherValue;
        $key = base64_decode($key);
        openssl_private_decrypt($key, $k, $this->privatePEM, OPENSSL_PKCS1_OAEP_PADDING);
        $data = (string)$xml->EncryptedAssertion->EncryptedData->CipherData->CipherValue;
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $data = substr($data, 16);
        $data = openssl_decrypt($data, 'aes-128-cbc', $k, OPENSSL_ZERO_PADDING | OPENSSL_RAW_DATA, $iv);
        if (!$data) {
            throw new \Exception('Could not decrypt');
        }
        $data = explode(':Assertion>', $data)[0] . ':Assertion>';
        if ($this->remotePEM) {
            $res = \vakata\certificate\P7S::validateXML(
                $data,
                \vakata\certificate\Certificate::fromString($this->remotePEM)
            );
            if (!count($res) || !isset($res[0]) || !isset($res[0]['valid']) || !$res[0]['valid']) {
                throw new \Exception('Invalid signature');
            }
        }

        $xml = simplexml_load_string(preg_replace(['(\<[a-z0-9]+\:)i', '(\</[a-z0-9]+\:)i'], ['<', '</'], $data) ?? '');
        if (!$xml) {
            throw new \Exception('Could not parse XML');
        }
        if (
            isset($id) &&
            $id != (string)($xml->Subject->SubjectConfirmation->SubjectConfirmationData['InResponseTo'] ?? '')
        ) {
            throw new \Exception('Invalid ID');
        }
        $data = [];
        foreach ($xml->AttributeStatement->Attribute as $a) {
            $data[str_replace('urn:egov:bg:eauth:2.0:attributes:', '', (string)$a['Name'])] =
                rawurldecode((string)$a->AttributeValue);
        }
        return $data;
    }
    protected function sign(string $data): string
    {
        $key = $this->privatePEM;
        $certificate = $this->certificatePEM;

        $xml = new \DOMDocument();
        $xml->preserveWhiteSpace = true;
        $xml->formatOutput = false;
        $xml->loadXML($data ?: throw new \RuntimeException());
        if (!$xml->documentElement) {
            throw new \Exception('Invalid XML');
        }
        $element = $xml->documentElement;
        $canonicalData = $element->C14N(true, false);
        $digestValue = base64_encode(openssl_digest($canonicalData, 'sha256', true) ?: '');
        $signatureElement = $xml->createElement('Signature');
        $signatureElement->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');
        $xml->documentElement->appendChild($signatureElement);
        $signedInfoElement = $xml->createElement('SignedInfo');
        $signatureElement->appendChild($signedInfoElement);
        $cmElement = $xml->createElement('CanonicalizationMethod');
        $cmElement->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $signedInfoElement->appendChild($cmElement);
        $signatureMethodElement = $xml->createElement('SignatureMethod');
        $signatureMethodElement->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        $signedInfoElement->appendChild($signatureMethodElement);
        $referenceElement = $xml->createElement('Reference');
        $referenceElement->setAttribute('URI', '');
        $signedInfoElement->appendChild($referenceElement);
        $transformsElement = $xml->createElement('Transforms');
        $referenceElement->appendChild($transformsElement);
        $transformElement = $xml->createElement('Transform');
        $transformElement->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $transformsElement->appendChild($transformElement);
        $transformElement = $xml->createElement('Transform');
        $transformElement->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $transformsElement->appendChild($transformElement);
        $digestMethodElement = $xml->createElement('DigestMethod');
        $digestMethodElement->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
        $referenceElement->appendChild($digestMethodElement);
        $digestValueElement = $xml->createElement('DigestValue', $digestValue);
        $referenceElement->appendChild($digestValueElement);
        $signatureValueElement = $xml->createElement('SignatureValue', '');
        $signatureElement->appendChild($signatureValueElement);
        $keyInfoElement = $xml->createElement('KeyInfo');
        $signatureElement->appendChild($keyInfoElement);
        $keyValueElement = $xml->createElement('KeyValue');
        $keyInfoElement->appendChild($keyValueElement);
        $rsaKeyValueElement = $xml->createElement('RSAKeyValue');
        $keyValueElement->appendChild($rsaKeyValueElement);
        $pkey = openssl_pkey_get_private($key) ?: throw new \RuntimeException('Invalid key');
        $details = openssl_pkey_get_details($pkey) ?: throw new \RuntimeException('Invalid key');
        $modulusElement = $xml->createElement('Modulus', base64_encode($details['rsa']['n']));
        $rsaKeyValueElement->appendChild($modulusElement);
        $exponentElement = $xml->createElement('Exponent', base64_encode($details['rsa']['e']));
        $rsaKeyValueElement->appendChild($exponentElement);
        if ($certificate) {
            $x509DataElement = $xml->createElement('X509Data');
            $keyInfoElement->appendChild($x509DataElement);
            $x509CertificateElement = $xml->createElement(
                'X509Certificate',
                str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $certificate)
            );
            $x509DataElement->appendChild($x509CertificateElement);
        }
        $c14nSignedInfo = $signedInfoElement->C14N(true, false);
        openssl_sign($c14nSignedInfo, $signatureValue, $key, OPENSSL_ALGO_SHA256);
        $xpath = new \DOMXPath($xml);
        $temp = $xpath->query('//SignatureValue', $signatureElement);
        if (!$temp) {
            throw new \RuntimeException('Could not find signature');
        }
        $signatureValueElement = $temp->item(0);
        if (!$signatureValueElement) {
            throw new \RuntimeException('Could not find signature');
        }
        $signatureValueElement->nodeValue = base64_encode($signatureValue);
        return $xml->saveXML() ?: '';
    }

    public function serviceURL(): string
    {
        return 'https://eauth.egov.bg/SingleSignOnService';
    }
    public function supports(array $data = []) : bool
    {
        return isset($_POST['SAMLResponse']) &&
               parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === parse_url($this->returnURL, PHP_URL_PATH);
    }
    public function authenticate(array $data = []): Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Invalid URL');
        }
        try {
            $data = $this->response($_POST['SAMLResponse']);
        } catch (\Exception $ignore) {
            throw new AuthenticationException();
        }
        if (!isset($data['personIdentifier'])) {
            throw new AuthenticationException();
        }
        return new Credentials(
            substr(strrchr(get_class($this), '\\'), 1),
            $data['personIdentifier'],
            array_merge([
                'mail' => $data['email'] ?? null,
                'name' => $data['birthName'] ?? $data['latinName'] ?? $data['personIdentifier']
            ], $data)
        );
    }
}
