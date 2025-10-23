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

        $existing = User::where('email', $validated['email'])
            ->orWhere('username', $validated['username'])
            ->when($normalizedPhone, function ($query) use ($normalizedPhone) {
                $query->orWhere('phone_number', $normalizedPhone);
            })
            ->first();

        if ($existing) {
            $conflicts = [];

            if (isset($validated['email']) && $existing->email === $validated['email']) {
                $conflicts[] = 'email';
            }
            if (isset($validated['username']) && $existing->username === $validated['username']) {
                $conflicts[] = 'username';
            }
            if ($normalizedPhone && $existing->phone_number === $normalizedPhone) {
                $conflicts[] = 'phone_number';
            }

            return response()->json([
                'message' => 'Conflict: one or more fields are already in use.',
                'conflicts' => $conflicts,           // e.g. ['email', 'username']
                'errors' => array_combine($conflicts, array_map(fn($f)=>["The $f is already taken."], $conflicts))
            ], 409);
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
            'last_login_at' => null,
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
        $validated = $request->validate([
            'login' => 'required|string', // accepts email, username or phone number
            'password' => 'required|string|min:6',
            'remember_me' => 'boolean',
        ]);

        $login = $validated['login'];
        $password = $validated['password'];
        $rememberMe = (bool) ($validated['remember_me'] ?? false);

        $loginKey = 'username';
        $loginValue = $login;

        // email
        if (filter_var($login, FILTER_VALIDATE_EMAIL)) {
            $loginKey = 'email';
            $loginValue = strtolower($login);
        } else {
            // try parsing as phone with libphonenumber
            try {
                $phoneUtil = PhoneNumberUtil::getInstance();
                // if user supplies +E.164 or international prefix parse with null,
                // otherwise parse with null as well (libphonenumber will attempt best-effort)
                $numberProto = $phoneUtil->parse($login, null);

                if ($phoneUtil->isValidNumber($numberProto)) {
                    $loginKey = 'phone_number';
                    $loginValue = $phoneUtil->format($numberProto, PhoneNumberFormat::E164);
                }
                // if not valid, we leave loginKey as username
            } catch (NumberParseException $e) {
                // parsing failed — treat as username
            }
        }

        $user = User::where($loginKey, $loginValue)->first();

        if (!$user || !Hash::check($password, $user->password)) {
            return response()->json(['message' => 'The provided credentials are incorrect.'], 401);
        }

        // update last login server-side
        $user->update(['last_login_at' => now()]);

        // create token and set expiry based on remember_me
        $newToken = $user->createToken('auth_token'); // NewAccessToken
        $plainText = $newToken->plainTextToken;

        // modify underlying PersonalAccessToken model if available
        if (! empty($newToken->accessToken)) {
            $tokenModel = $newToken->accessToken;
            $tokenModel->expires_at = $rememberMe ? now()->addDays(30) : now()->addDay();
            $tokenModel->save();
        }

        return response()->json([
            'user' => $user,
            'token' => $plainText,
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
