<?php
namespace App\Services;

use App\Traits\ConsumesExternalService;

class User2Service{
    use ConsumesExternalService;
    /**
    * The base uri to consume the User1 Service
        * @var string
    */
    public $baseUri;

    public function __construct()
    {
        $this->baseUri = config('services.users2.base_uri');
    }
    /**
    * Obtain the full list of Users from User1 Site
    * @return string
    */
    public function obtainUsers2()
    {
        return $this->performRequest('GET','/users'); //<—this code will call the GET localhost:8000/users (our site1)
    }
    /**
    * Create one user using the User1 service
    * @return string
    */
    public function createUser2($data)
    {
        return $this->performRequest('POST', '/users', $data);
    }
    /**
    * Obtain one single user from the User1 service
    * @return string4.
    */
    public function obtainUser2($id)
    {
    return $this->performRequest('GET', "/users/{$id}");
    }
    /**
    * Update an instance of user1 using the User1 service
    * @return string
    */
    public function editUser2($data, $id)
    {
    return $this->performRequest('PUT', "/users/{$id}", $data);
    }
    /**
    * Remove an existing user
    * @return Illuminate\Http\Response
    */
    public function deleteUser2($id)
    {
        return $this->performRequest('DELETE', "/users/{$id}");
    }
}