<?php

namespace App\Services\Domain;

use Illuminate\Http\UploadedFile;
use RuntimeException;

class BulkDomainFileParser
{
    /**
     * @return list<string>
     */
    public function parse(UploadedFile $file): array
    {
        $path = $file->getRealPath();
        if ($path === false) {
            throw new RuntimeException('Unable to read uploaded file.');
        }

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new RuntimeException('Unable to open uploaded file.');
        }

        $maxRows = (int) config('domain_checker.max_upload_rows', 2000);
        $values = [];
        $rowCount = 0;

        try {
            // Skip UTF-8 BOM if present.
            $bom = fread($handle, 3);
            if ($bom !== "\xEF\xBB\xBF") {
                rewind($handle);
            }

            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#')) {
                    continue;
                }

                // CSV: take first column; TXT: whole line.
                $parts = str_getcsv($line);
                $value = trim((string) ($parts[0] ?? ''));
                $value = trim($value, "\"'");

                if ($value === '' || strcasecmp($value, 'domain') === 0 || strcasecmp($value, 'email') === 0) {
                    continue;
                }

                $rowCount++;
                if ($rowCount > $maxRows) {
                    throw new RuntimeException("Upload exceeds the maximum of {$maxRows} domains.");
                }

                $values[] = $value;
            }
        } finally {
            fclose($handle);
        }

        if ($values === []) {
            throw new RuntimeException('No domains or emails found in the file.');
        }

        return $values;
    }
}
