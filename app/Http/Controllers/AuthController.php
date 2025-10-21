<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use libphonenumber\PhoneNumberUtil;
use libphonenumber\PhoneNumberFormat;
use libphonenumber\NumberParseException;

class AuthController extends Controller
{
    // REGISTER
    public function register(Request $request)
    {
        $validated = $request->validate([
            'username' => 'required|string|max:255|unique:users,username',
            'full_name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
            'date_of_birth' => 'nullable|date',
            'profile_picture' => 'nullable|image|max:2048',
            'is_active' => 'boolean',
            'role' => 'in:user,admin',
            'phone_number' => 'nullable|string|max:20', // raw input (local or E.164)
            'country_code' => 'nullable|string|size:2', // optional ISO2 region for parsing (e.g. US, IQ)
            'last_login_at' => 'nullable|date',
        ]);

        $profilePath = null;
        if ($request->hasFile('profile_picture')) {
            $profilePath = $request->file('profile_picture')->store('profile_pictures', 'public');
        }

        // normalize phone to E.164 if provided
        $normalizedPhone = null;
        if (!empty($validated['phone_number'])) {
            $phoneUtil = PhoneNumberUtil::getInstance();
            $raw = $validated['phone_number'];
            $region = isset($validated['country_code']) ? strtoupper($validated['country_code']) : null; // optional ISO2 region (e.g. 'US', 'IQ')
            try {
                if (strpos($raw, '+') === 0) {
                    $numberProto = $phoneUtil->parse($raw, null);
                } else {
                    $numberProto = $phoneUtil->parse($raw, $region);
                }

                if (! $phoneUtil->isValidNumber($numberProto)) {
                    return response()->json(['message' => 'Invalid phone number'], 422);
                }

                $normalizedPhone = $phoneUtil->format($numberProto, PhoneNumberFormat::E164);
            } catch (NumberParseException $e) {
                return response()->json(['message' => 'Invalid phone number'], 422);
            }
        }

        $user = User::create([
            'username' => $validated['username'],
            'full_name' => $validated['full_name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'date_of_birth' => $validated['date_of_birth'],
            'profile_picture' => $profilePath,
            'is_active' => $validated['is_active'] ?? true,
            'role' => $validated['role'],
            'phone_number' => $normalizedPhone,
            'last_login_at' => $validated['last_login_at'],
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token
        ], 201);
    }

    // LOGIN
    public function login(Request $request)
    {
        $request->validate([
            'login' => 'required|string', // accepts email, username or phone number
            'password' => 'required',
            'remember_me' => 'boolean',
        ]);

        $login = $request->input('login');

        $user = User::where('email', $login)
            ->orWhere('username', $login)
            ->orWhere('phone_number', $login)
            ->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'The provided credentials are incorrect.'
            ], 401);
        }

        // optional: update last login timestamp
        $user->update(['last_login_at' => now()]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token
        ]);
    }

    // LOGOUT
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out']);
    }

    // CURRENT USER
    public function me(Request $request)
    {
        return response()->json($request->user());
    }
}
