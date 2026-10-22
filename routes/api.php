<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\PasswordResetController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/register', [AuthController::class, 'register']);

Route::post('/login', [AuthController::class, 'login']);

Route::post('/forgot-password', [
    PasswordResetController::class,
    'sendResetLink',
]);

Route::post('/reset-password', [
    PasswordResetController::class,
    'resetPassword',
]);

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');
