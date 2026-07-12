// Client-side XSS: insertAdjacentHTML with request-derived input
const search = new URLSearchParams(window.location.search);
document.getElementById('target').insertAdjacentHTML('beforeend', search.get('content'));