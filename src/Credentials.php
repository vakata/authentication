<?php

namespace vakata\authentication;

class Credentials
{
    protected $provider;
    protected $id;
    protected $data;

    public function __construct(string $provider, string $id, array $data = [])
    {
        $this->provider = $provider;
        $this->id = $id;
        $this->data = $data;
    }
    public function getID() : string
    {
        return $this->id;
    }
    public function getProvider() : string
    {
        return $this->provider;
    }
    public function toArray() : array
    {
        return array_merge($this->data, [ 'id' => $this->id, 'provider' => $this->provider ]);
    }
    public function get(string $key, $default = null)
    {
        return $this->toArray()[$key] ?? $default;
    }
}