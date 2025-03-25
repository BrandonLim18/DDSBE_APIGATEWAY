<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function __construct()
    {
        // Exclude these methods from JWT check
        $this->middleware('auth:api', ['except' => ['login', 'register', 'refresh', 'logout']]);
    }

    public function register(Request $request)
    {
        // Validate the incoming request data
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string',
            'email'    => 'required|email|unique:users',
            'password' => 'required|string|min:6|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // Create a new user record
        $user = new User();
        $user->name     = $request->input('name');
        $user->email    = $request->input('email');
        $user->password = Hash::make($request->input('password'));
        $user->save();

        return response()->json(['message' => 'User registered successfully'], 201);
    }



    // Login and issue token
    public function login(Request $request)
    {
        $this->validate($request, [
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        $credentials = $request->only(['email', 'password']);

        if (!$token = Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    // Get current user
    public function me()
    {
        return response()->json(auth()->user());
    }

    // Invalidate token and logout
    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    // Refresh JWT token
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    // Token response structure
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'user'         => auth()->user(),
            'expires_in'   => auth()->factory()->getTTL() * 60 * 24,
        ]);
    }
}
