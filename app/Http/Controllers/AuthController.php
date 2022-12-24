<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use App\Models\PasswordReset;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * gawe auth AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:6|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = User::create([
            'name' => request('name'),
            'email' => request('email'),
            'password' => Hash::make(request('password')),
        ]);
        if ($user) {
            return response()->json(['success' => true, 'message' => 'Pendaftaran Berhasil']);
        } else {
            return response()->json(['success' => false, 'message' => 'Pendaftaran Gagal']);
        }
    }


    //login menggunakan jwt
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $validator = Validator::make(request()->all(), [
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Email dan password yang anda masukkan tidak sesuai'], 401);
        }

        return $this->respondWithToken($token);
    }

    //me/profile user
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */

    public function me()
    {
        return response()->json(auth()->user());
    }

    //ganti me dengan dibawah ini untuk menyamarkan nama akun
    // public function me()
    // {
    //     try {
    //         return response()->json(['success' => true, 'data' => auth()->user()]);
    //     } catch (\exception $e) {
    //         return response()->json(['success' => false, 'msg' => $e->getMessage()]);
    //     }
    // }


    //logout user dari profile
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        try {
            auth()->logout();

            return response()->json(['success' => true, 'message' => 'Successfully logged out']);
        } catch (\exception $e) {
            return response()->json(['success' => false, 'msg' => $e->getMessage()]);
        }
    }


    //refresh token
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }


    //jwt token
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'succes' => true,
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    //refresh token e
    public function refreshToken()
    {
        if (auth()->user()) {
            return $this->responsewithToken(auth()->refresh());
        } else {
            return response()->json(['success' => false, 'message' => 'user not authenticated']);
        }
    }

    //reset password yang ada
    public function forgetPassword(Request $request)
    {
        try {
            $user = User::where('email', $request->email)->get();
            if (count($user) > 0) {
                $token = Str::random(40);
                $domain = URL::to('/');
                $url = $domain . '/reset-password?token=' . $token;

                $data['url'] = $url;
                $data['email'] = $request->email;
                $data['title'] = "password reset";
                $data['body'] = "Silahkan klik link berikut ini untuk reset password anda";

                Mail::send('forgetPasswordMail', ['data' => $data], function ($message) use ($data) {
                    $message->to($data['email'])->subject($data['title']);
                });

                $datetime = Carbon::now()->format('Y-m-d H:i:s');
                PasswordReset::updateOrCreate(
                    ['email' => $request->email],
                    [
                        'email' => $request->email,
                        'token' => $token,
                        'created_at' => $datetime
                    ]
                );

                return response()->json(['success' => true, 'message' => 'Periksa email anda untuk reset password'()]);
            } else {
                return response()->json(['success' => false, 'message' => 'user not found'()]);
            }
        } catch (\Exception $e) {
            return response()->json(['success' => false, 'message' => $e->getMessage()]);
        }
    }
}
