<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class BulkDnsCheckRequest extends FormRequest
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
        $maxKb = (int) config('domain_checker.max_upload_kilobytes', 2048);

        return [
            'file' => [
                'required',
                'file',
                'max:'.$maxKb,
                'extensions:csv,txt',
            ],
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
            'file.required' => 'Please upload a CSV or TXT file.',
            'file.extensions' => 'Only CSV or TXT files are allowed.',
            'file.max' => 'The upload may not be greater than :max kilobytes.',
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
