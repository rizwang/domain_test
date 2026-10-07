<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SingleDnsCheckRequest extends FormRequest
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
            'dkim_selector' => ['nullable', 'string', 'max:63', 'regex:/^[a-zA-Z0-9._-]+$/'],
            'include_all_dns' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'input.required' => 'Please enter a domain or email address.',
            'dkim_selector.regex' => 'DKIM selector contains invalid characters.',
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'include_all_dns' => filter_var(
                $this->input('include_all_dns', false),
                FILTER_VALIDATE_BOOLEAN
            ),
            'dkim_selector' => $this->filled('dkim_selector')
                ? trim((string) $this->input('dkim_selector'))
                : null,
        ]);
    }
}
