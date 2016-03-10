<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

class TOTP implements AuthenticationInterface
{
    protected $secret = null;
    protected $options = [];

    public function __construct($secret, array $options = [])
    {
        $this->secret = $secret;
        $this->options  = array_merge([
            'title'         => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'TOTP',
            'code_timeout'  => 60,
            'code_length'   => 6,
            'slice_length'  => 30
        ], $options);
    }

    protected function generateCode($now = null) {
        $secret = $this->getSecret();
        if ($now === null) {
            $now = floor(microtime(true) / $this->options['slice_length']);
        }
        $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $now), static::base32_decode($secret), true);
        $offs = ord($hash[19]) & 0xf;
        $hash = (
            ((ord($hash[$offs+0]) & 0x7f) << 24 ) |
            ((ord($hash[$offs+1]) & 0xff) << 16 ) |
            ((ord($hash[$offs+2]) & 0xff) << 8  ) |
             (ord($hash[$offs+3]) & 0xff)
        ) % pow(10, $this->options['code_length']);
        return str_pad($hash, $this->options['code_length'], '0', STR_PAD_LEFT);
    }
    protected static function base32_decode($b32) {
        $lut = [
            "A" => 0,   "B" => 1,   "C" => 2,   "D" => 3,
            "E" => 4,   "F" => 5,   "G" => 6,   "H" => 7,
            "I" => 8,   "J" => 9,   "K" => 10,  "L" => 11,
            "M" => 12,  "N" => 13,  "O" => 14,  "P" => 15,
            "Q" => 16,  "R" => 17,  "S" => 18,  "T" => 19,
            "U" => 20,  "V" => 21,  "W" => 22,  "X" => 23,
            "Y" => 24,  "Z" => 25,  "2" => 26,  "3" => 27,
            "4" => 28,  "5" => 29,  "6" => 30,  "7" => 31
        ];
        $b32 = strtoupper($b32);
        $l = strlen($b32);
        $n = 0;
        $j = 0;
        $binary = "";
        for ($i = 0; $i < $l; $i++) {
            $n = $n << 5;               // Move buffer left by 5 to make room
            $n = $n + $lut[$b32[$i]];   // Add value into buffer
            $j = $j + 5;                // Keep track of number of bits in buffer
            if ($j >= 8) {
                $j = $j - 8;
                $binary .= chr(($n & (0xFF << $j)) >> $j);
            }
        }
        return $binary;
    }
    protected static function base32_encode($str) {
        $lut = [
            'A',    'B',    'C',    'D',
            'E',    'F',    'G',    'H',
            'I',    'J',    'K',    'L',
            'M',    'N',    'O',    'P',
            'Q',    'R',    'S',    'T',
            'U',    'V',    'W',    'X',
            'Y',    'Z',    '2',    '3',
            '4',    '5',    '6',    '7'
        ];
        $bin = '';
        foreach (str_split($str) as $s) {
            $bin .= str_pad(decbin(ord($s)), 8, 0, STR_PAD_LEFT);
        }
        $bin = explode(' ', trim(chunk_split($bin, 5, ' ')));
        if (count($bin) % 8 !== 0) {
            $bin = array_pad($bin, count($bin) + (8 - count($bin) % 8), null);
        }
        $b32 = '';
        foreach ($bin as $b) {
            $b32 .= is_null($b) ? '=' : $lut[bindec(str_pad($b, 5, 0, STR_PAD_RIGHT))];
        }
        return $b32;
    }

    public function getSecret()
    {
        return substr(static::base32_encode(sha1($this->secret)), 0, 16);
    }
    public function getSecretUri()
    {
        return 'otpauth://totp/'.$this->options['title'].'?secret='.$this->getSecret();
    }
    public function getQRCode($size = 200)
    {
        $image  = 'https://chart.googleapis.com/chart';
        $image .= '?chs='.$size.'x'.$size.'&chld=M|0&cht=qr&chl=' . urlencode($this->getSecretUri());
        return 'data:image/png;base64,' . @base64_encode(file_get_contents($image));
    }

    public function supports(array $data = [])
    {
        return isset($data['totp']);
    }
    public function authenticate(array $data = [])
    {
        if (!isset($data['totp'])) {
            throw new AuthenticationException('Missing credentials');
        }
        $isValid = false;
        $data['totp'] = str_replace(' ', '', $data['totp']);
        $now = floor(microtime(true) / $this->options['slice_length']);
        $ctm = ceil($this->options['code_timeout'] / $this->options['slice_length']);
        for ($i = -$ctm; $i <= $ctm; $i++) {
            if ($this->generateCode($now + $i) === $data['totp']) {
                $isValid = true;
                break;
            }
        }
        if (!$isValid) {
            throw new AuthenticationException('Invalid credentials');
        }
        return new JWT([
            'provider' => 'totp',
            'id'       => $this->getSecret(),
            'name'     => null,
            'mail'     => null
        ]);
    }
}
