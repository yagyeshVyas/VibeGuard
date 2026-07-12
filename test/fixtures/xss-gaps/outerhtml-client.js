// Client-side XSS: outerHTML with request-derived input
const params = new URLSearchParams(window.location.search);
document.getElementById('content').outerHTML = params.get('html');