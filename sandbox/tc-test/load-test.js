import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
    duration: '10s',
    vus: 10,
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(95)', 'p(99)', 'p(99.9)']
}

export default function () {
    http.get('http://localhost:8080');
    sleep(1);
}