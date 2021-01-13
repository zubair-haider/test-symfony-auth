<?php
namespace App\Controller;

use Lexik\Bundle\JWTAuthenticationBundle\Security\User\JWTUser;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class AuthController extends ApiController
{

    public function register(Request $request, HttpClientInterface $client)
    {
        $request = $this->transformJsonBody($request);
        $password = $request->get('password');
        $email = $request->get('email');
        $roles = $request->get('roles');

        if (empty($password) || empty($email)) {
            return $this->respondValidationError("Invalid Username or Password or Email");
        }


        $response = $client->request(
            'POST',
            "http://127.0.0.1:8000/register",
            [
                'json' => ['email' => $email, "password" => $password,"roles"=>$roles],
            ]
        );
        $data = $response->toArray();

        return $this->respondWithSuccess($data);
    }

    public function login(Request $request, HttpClientInterface $client, JWTTokenManagerInterface $JWTManager)
    {
        $request = $this->transformJsonBody($request);
        $password = $request->get('password');
        $email = $request->get('email');

        $response = $client->request(
            'POST',
            "http://127.0.0.1:8000/login",
            [
                'json' => ['username' => $email, "password" => $password],
            ]
        );
        $data = $response->toArray();
        $roles = $data['roles'];
        $email = $data['username'];
        $user = new JWTUser($email, $roles);
        $token = $JWTManager->create($user);
        $returnData = ["data" => $data, "token" => $token];
        return $this->respondWithSuccess($returnData);
    }
}
