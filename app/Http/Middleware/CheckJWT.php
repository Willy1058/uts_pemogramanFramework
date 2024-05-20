<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;

class CheckJWT
{
    public function handle(Request $request, Closure $next)
    {
        $jwt = $request->bearerToken();

        // Cek apakah token di-blacklist
        if (Cache::has('blacklisted_token:' . $jwt)) {
            return response()->json(['message' => 'Token is blacklisted'], 401);
        }

        try {
            $decoded = JWT::decode($jwt, new Key(env('FIREBASE_SECRET_KEY'), 'HS256'));

            // Simpan informasi pengguna dari token
            $request->setUserResolver(function () use ($decoded) {
                return $decoded;
            });
        } catch (\Exception $e) {
            return response()->json(['message' => 'Token is invalid or expired'], 401);
        }

        return $next($request);
    }
}
