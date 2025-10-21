<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasFactory, HasApiTokens;

    protected $fillable = [
        'username',
        'full_name',
        'email',
        'password',
        'date_of_birth',
        'profile_picture',
        'is_active',
        'role',
        'phone_number',
        'last_login_at',
    ];

    protected $hidden = [
        'password'
    ];
}
