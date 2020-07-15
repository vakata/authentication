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
        $data = [ 'id' => $this->id, 'provider' => $this->provider ];
        if (isset($this->data['name'])) {
            $data['name'] = $this->data['name'];
        }
        if (isset($this->data['mail'])) {
            $data['mail'] = $this->data['mail'];
        }
        return $data;
    }
    public function getData() {
        return $this->data;
    }
    public function get(string $key, $default = null)
    {
        $data = array_merge($this->data, [ 'id' => $this->id, 'provider' => $this->provider ]);
        return $data[$key] ?? $default;
    }
}