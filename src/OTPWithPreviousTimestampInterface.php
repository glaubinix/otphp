<?php

declare(strict_types=1);

namespace OTPHP;

interface OTPWithPreviousTimestampInterface extends OTPInterface
{
    /**
     * Verify method which prevents previously used codes from being used again. The passed values are in seconds.
     *
     * @param non-empty-string $otp
     * @param null|0|positive-int $timestamp
     * @param null|0|positive-int $leeway
     * @param null|0|positive-int $previousTimestamp
     * @return int|false the timestamp matching the otp on success, and false on error
     */
    public function verifyWithPreviousTimestamp(string $otp, null|int $timestamp = null, null|int $leeway = null, null|int $previousTimestamp = null): int|false;
}
