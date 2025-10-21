<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    // LIST ALL USERS
    public function index()
    {
        return User::all();
    }

    // SHOW A SINGLE USER
    public function show(User $user)
    {
        return $user;
    }

    // UPDATE USER
    public function update(Request $request, User $user)
    {
        $validated = $request->validate([
            'username' => 'sometimes|string|max:255|unique:users,username,' . $user->id,
            'full_name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email|unique:users,email,' . $user->id,
            'password' => 'sometimes|string|min:6|confirmed',
            'date_of_birth' => 'sometimes|date',
            'profile_picture' => 'sometimes|image|max:2048',
            'is_active' => 'sometimes|boolean',
            'role' => 'sometimes|in:user,admin',
            'phone_number' => 'sometimes|string|max:15',           
        ]);

        if (isset($validated['password'])) {
            $validated['password'] = Hash::make($validated['password']);
        }

        $user->update($validated);

        return $user;
    }

    // DELETE USER
    public function destroy(User $user)
    {
        $user->delete();
        return response()->json(['message' => 'User deleted']);
    }
}
