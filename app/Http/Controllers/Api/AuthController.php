<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rules\Password;


class AuthController extends Controller
{
    public function register(Request $request)  {
        $request->validate([
            'name'=>'required',
            'email'=>'required|email|unique:users,email',
            'password'=> ['required', 'confirmed', Password::min(8)],
        ]);

      $user =  User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' =>bcrypt($request->password),
        ]);
        
        $token = $user->createToken('token-name', ['server:update'])->plainTextToken;
        return response()->json([
            'message' => 'Register Complete',
            'data' => $user,
            'token' => $token
        ], 200);
    }

    public function login(Request $request) {
        $request->validate([
            'email'=>'required',
            'password'=> ['required'],
        ]);
            if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
                $user = User::where('email', $request->email)->first();
                $token = $user->createToken('token-name', ['server:update'])->plainTextToken;
                return response()->json([
                   'message' => 'Login Complete, Dont forgot your account',
                   'data' => $user,
                   'token' => $token
                ], 401);
            }else{
                return response()->json([
                    'message' => 'Email And Password Wrong, Check Again',
                ], 401);
            }
            
    }

    public function logout() {
        auth()->user()->tokens()->delete();

        return response()->json([
            'message' => 'Logout Complete',
        ], 200);
    }


}
