<?php
namespace vakata\authentication\certificate;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;
use vakata\certificate\Certificate;

/**
 * A class for client certificate based authentication.
 */
class CertificateAdvanced implements AuthenticationInterface
{
    protected $options;
    protected $callback;
    protected $roots = [];

    public function __construct(array $options = [], ?callable $callback = null)
    {
        $this->options = array_merge(
            [
                'crl'        => true,
                'ocsp'       => true,
                'selfsigned' => false,
                'roots'      => null
            ],
            $options
        );
        $this->callback = $callback;
        if (isset($this->options['roots'])) {
            foreach ($this->options['roots'] as $root) {
                $root = Certificate::fromString($root);
                $this->roots[$root->getSubjectKeyIdentifier()] = $root;
            }
        }
    }
    /**
     * Does the auth class support this input
     * @param  array    $data the auth input
     * @return boolean        is a client certificate is supplied
     */
    public function supports(array $data = []) : bool
    {
        return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' && isset($_SERVER['SSL_CLIENT_CERT']);
    }
    /**
     * Authenticate using the supplied certificate. Returns a JWT token or throws an AuthenticationException.
     * @param  array        $data not used in this class
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!isset($_SERVER['SSL_CLIENT_CERT'])) {
            throw new CertificateExceptionMissing();
        }
        
        try {
            $certificate = Certificate::fromRequest();
            if ($certificate->isExpired()) {
                throw new CertificateExceptionInvalid();
            }
            if (!$this->options['selfsigned'] && $certificate->isSelfSigned()) {
                throw new CertificateExceptionInvalid();
            }
            if (isset($this->options['roots']) && !$certificate->isSelfSigned()) {
                if (!isset($this->roots[$certificate->getAuthorityKeyIdentifier()])) {
                    throw new CertificateExceptionInvalid();
                }
                $certificate->setCA($this->roots[$certificate->getAuthorityKeyIdentifier()]);
                if (!$certificate->isSignatureValid()) {
                    throw new CertificateExceptionInvalid();
                }
                if ($this->options['ocsp'] && $certificate->hasOCSP() && $certificate->isRevokedOCSP()) {
                    throw new CertificateExceptionInvalid();
                }
            }
            if ($this->options['crl'] && $certificate->hasCRL() && $certificate->isRevokedCRL()) {
                throw new CertificateExceptionInvalid();
            }
            if (isset($this->callback) && !call_user_func($this->callback, $certificate)) {
                throw new CertificateExceptionInvalid();
            }
        } catch (\Exception $e) {
            throw new CertificateExceptionInvalid();
        }
        $data = $certificate->getSubjectData();
        if (isset($data['commonName'])) {
            $data['name'] = $data['commonName'];
        }
        if (isset($data['emailAddress'])) {
            $data['mail'] = $data['emailAddress'];
        }
        return new Credentials(
            substr(strrchr(get_class($this), '\\'), 1),
            $certificate->getAuthorityKeyIdentifier() . '/' . $certificate->getSerialNumber(),
            $data
        );
    }
}
