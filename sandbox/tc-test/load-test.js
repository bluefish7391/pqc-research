
/**
 * k6 does not support standardized quantum-safe protocols.
 * This script will not work with OQS's web server image.
 */

import https from 'k6/http';
import { sleep } from 'k6';

export const options = {
    insecureSkipTLSVerify: true,
    duration: '10s',
    vus: 10,
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(95)', 'p(99)', 'p(99.9)']
}

export default function () {
    https.get('https://localhost:8443');
    sleep(1);
}