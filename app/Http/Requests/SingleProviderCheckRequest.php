<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SingleProviderCheckRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'input' => ['required', 'string', 'max:255'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'input.required' => 'Please enter a domain or email address.',
        ];
    }
}
