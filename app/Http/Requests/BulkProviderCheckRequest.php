<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class BulkProviderCheckRequest extends FormRequest
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
}
