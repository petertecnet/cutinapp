<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CheckApiAuthentication
{
    public function handle($request, Closure $next)
    {
        if ($request->expectsJson() && ! $request->user()) {
            return response()->json(['message' => 'Usuário não autenticado'], 401);
        }

        return $next($request);
    }
}
