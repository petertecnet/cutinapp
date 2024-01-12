<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use App\Models\User;
use App\Mail\VerificationCodeMail;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    protected function getValidationMessages()
{
    return [
        'name.required' => 'O campo nome é obrigatório.',
        'email.required' => 'O campo e-mail é obrigatório.',
        'email.email' => 'O e-mail deve ser um endereço de e-mail válido.',
        'email.unique' => 'Este e-mail já está sendo utilizado por outro usuário.',
        'password.required' => 'O campo senha é obrigatório.',
        'password.min' => 'A senha deve ter no mínimo :min caracteres.',
        'password.regex' => 'A senha deve conter pelo menos uma letra maiúscula, uma letra minúscula, um número e um caractere especial.',
    ];
}

    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => 'required|string',
                'email' => 'required|string|email|unique:users',
                'password' => [
                    'required',
                    'string',
                    'min:6',
                    'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/',
                ],
            ], $this->getValidationMessages());
    
            $verificationCode = Str::random(4); 
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => bcrypt($request->password),
                'verification_code' => $verificationCode,
            ]);
    
        $user->save();
            $token = $user->createToken('auth_token')->plainTextToken;
    

            Mail::to($user->email)->send(new VerificationCodeMail($verificationCode, $user));


            return response()->json(['token' => $token, 'user' => $user]);
        } catch (ValidationException $e) {
            // Se a exceção de validação ocorrer, retorne as mensagens de erro de validação personalizadas
            $errors = $e->errors();
            return response()->json(['message' => 'Erro de validação', 'errors' => $errors], 422);
        } catch (\Exception $e) {
            // Se ocorrer qualquer outro tipo de erro, retorne uma mensagem de erro genérica
            return response()->json(['message' => 'Erro durante o registro. Por favor, tente novamente.'], 500);
        }
    }
    


public function login(Request $request)
{
    $request->validate([
        'email' => 'required|string|email',
        'password' => 'required|string',
    ]);

    $user = User::where('email', $request->email)->first();

    if (!$user || !password_verify($request->password, $user->password)) { // Use password_verify
        return response()->json(['message' => 'As credenciais fornecidas estão incorretas.'], 401);
    }

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json(['token' => $token, 'user' => $user]);
}



public function logout(Request $request)
{
    try {
        $token = $request->bearerToken(); // Get the token from the request

        if ($request->user() && $token) {

            $request->user()->tokens()->delete();
            return response()->json(['message' => 'Logout realizado com sucesso.']);
        }

        return response()->json(['error' => 'Usuário não autenticado ou token ausente.'], 401);
    } catch (\Exception $e) {
        return response()->json(['error' => 'Erro durante o logout.'], 500);
    }
}

}
