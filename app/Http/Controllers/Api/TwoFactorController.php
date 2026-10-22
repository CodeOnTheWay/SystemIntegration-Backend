<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Laravel\Fortify\Fortify;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;

class TwoFactorController extends Controller
{
    public function setup(Request $request)
    {
        $user = $request->user();

        if ($user->hasEnabledTwoFactorAuthentication()) {
            return response()->json([
                'message' => 'Two-factor authentication is already enabled.',
            ], 409);
        }

        $secret = app(TwoFactorAuthenticationProvider::class)
            ->generateSecretKey();

        $user->forceFill([
            'two_factor_secret' => Fortify::currentEncrypter()
                ->encrypt($secret),
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ])->save();

        return response()->json([
            'message' => 'Scan the QR code with your authenticator app, then confirm with a code.',
            'qr_code_svg' => $user->fresh()->twoFactorQrCodeSvg(),
        ]);
    }

    public function confirm(
        Request $request,
        TwoFactorAuthenticationProvider $provider
    ) {
        $validated = $request->validate([
            'code' => ['required', 'digits:6'],
        ]);

        $user = $request->user();

        if (empty($user->two_factor_secret)) {
            return response()->json([
                'message' => 'Please set up two-factor authentication first.',
            ], 400);
        }

        if ($user->hasEnabledTwoFactorAuthentication()) {
            return response()->json([
                'message' => 'Two-factor authentication is already enabled.',
            ], 409);
        }

        $secret = Fortify::currentEncrypter()->decrypt(
            $user->two_factor_secret
        );

        if (! $provider->verify($secret, $validated['code'])) {
            return response()->json([
                'message' => 'Invalid authenticator code. Please try again.',
            ], 422);
        }

        $user->forceFill([
            'two_factor_confirmed_at' => now(),
        ])->save();

        return response()->json([
            'message' => 'Two-factor authentication enabled successfully.',
        ]);
    }
}
